import dotenv from "dotenv";
dotenv.config();

import express, {
  NextFunction,
  Request,
  Response
} from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt, { JwtPayload } from "jsonwebtoken";
import {
  initDb,
  pool,
  query,
  queryOne,
  transaction
} from "./database";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 3333;

function getEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} não configurado.`);
  }

  return value;
}

const JWT_SECRET = getEnv("JWT_SECRET");
const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS) || 10;

interface AuthenticatedRequest extends Request {
  userId?: number;
}

interface UserTokenPayload extends JwtPayload {
  id: number;
  email: string;
}

interface UserDatabase {
  id: number;
  email: string;
  nickname: string | null;
  password: string;
  goal: number;
}

interface StudyGroupDatabase {
  continuous_study_day: number;
  total_days_studied: number;
  total_experience_points: number;
  last_study_date: string | null;
  last_penalty_date: string | null;
}

interface UserWithStudyGroup {
  id: number;
  email: string;
  nickname: string | null;
  goal: number;
  continuous_study_day: number | null;
  total_days_studied: number | null;
  total_experience_points: number | null;
  last_study_date: string | null;
  last_penalty_date: string | null;
}

interface RankingUser {
  id: number;
  nickname: string | null;
  email: string;
  total_experience_points: number;
}

function getTodayString(): string {
  return new Date().toISOString().split("T")[0];
}

function getDiffDays(dateString: string): number {
  const today = new Date(`${getTodayString()}T00:00:00.000Z`);
  const date = new Date(`${dateString}T00:00:00.000Z`);

  return Math.floor(
    (today.getTime() - date.getTime()) /
      (1000 * 60 * 60 * 24)
  );
}

function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Token não informado"
    });
  }

  const [tokenType, token] = authHeader.split(" ");

  if (tokenType !== "Bearer" || !token) {
    return res.status(401).json({
      message: "Token inválido"
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET
    ) as UserTokenPayload;

    req.userId = decoded.id;

    next();
  } catch {
    return res.status(401).json({
      message: "Token inválido ou expirado"
    });
  }
}

async function applyStudyPenalty(userId: number): Promise<void> {
  const studyGroup =
    await queryOne<StudyGroupDatabase>(
      `
      SELECT
        continuous_study_day,
        total_days_studied,
        total_experience_points,
        last_study_date,
        last_penalty_date
      FROM studies_group
      WHERE user_id = $1
      `,
      [userId]
    );

  if (!studyGroup || !studyGroup.last_study_date) {
    return;
  }

  const todayString = getTodayString();

  if (studyGroup.last_penalty_date === todayString) {
    return;
  }

  const daysWithoutStudy = getDiffDays(
    studyGroup.last_study_date
  );

  if (daysWithoutStudy < 2) {
    return;
  }

  const lastPenaltyBaseDate =
    studyGroup.last_penalty_date ||
    studyGroup.last_study_date;

  const penaltyDiffDays = getDiffDays(
    lastPenaltyBaseDate
  );

  if (penaltyDiffDays <= 0) {
    return;
  }

  const penalty = penaltyDiffDays * 50;

  const newXp = Math.max(
    0,
    studyGroup.total_experience_points - penalty
  );

  await pool.query(
    `
    UPDATE studies_group
    SET
      continuous_study_day = 0,
      total_experience_points = $1,
      last_penalty_date = $2
    WHERE user_id = $3
    `,
    [newXp, todayString, userId]
  );
}

app.post("/create-user", async (req, res) => {
  try {
    const { email, nickname, password } = req.body;

    if (
      typeof email !== "string" ||
      email.trim().length === 0
    ) {
      return res.status(400).json({
        message: "Email é obrigatório"
      });
    }

    if (
      typeof password !== "string" ||
      password.length === 0
    ) {
      return res.status(400).json({
        message: "Senha é obrigatória"
      });
    }

    const normalizedEmail = email
      .trim()
      .toLowerCase();

    const hashedPassword = await bcrypt.hash(
      password,
      SALT_ROUNDS
    );

    const createdUser = await transaction(
      async client => {
        const userResult = await client.query<{
          id: number;
          email: string;
          nickname: string | null;
          goal: number;
        }>(
          `
          INSERT INTO users (
            email,
            nickname,
            password,
            goal
          )
          VALUES ($1, $2, $3, $4)
          RETURNING
            id,
            email,
            nickname,
            goal
          `,
          [
            normalizedEmail,
            nickname?.trim() || null,
            hashedPassword,
            100
          ]
        );

        const user = userResult.rows[0];

        await client.query(
          `
          INSERT INTO studies_group (
            user_id,
            continuous_study_day,
            total_days_studied,
            total_experience_points,
            last_study_date,
            last_penalty_date
          )
          VALUES ($1, $2, $3, $4, $5, $6)
          `,
          [user.id, 0, 0, 0, null, null]
        );

        return user;
      }
    );

    return res.status(201).json(createdUser);
  } catch (error: unknown) {
    console.error("Erro ao criar usuário:", error);

    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "23505"
    ) {
      return res.status(409).json({
        message: "Usuário já existe"
      });
    }

    return res.status(500).json({
      message: "Erro ao criar usuário"
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      email.trim().length === 0
    ) {
      return res.status(400).json({
        message: "Email é obrigatório"
      });
    }

    if (
      typeof password !== "string" ||
      password.length === 0
    ) {
      return res.status(400).json({
        message: "Senha é obrigatória"
      });
    }

    const normalizedEmail = email
      .trim()
      .toLowerCase();

    const user = await queryOne<UserDatabase>(
      `
      SELECT
        id,
        email,
        nickname,
        password,
        goal
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (!user) {
      return res.status(401).json({
        message: "Email ou senha inválidos"
      });
    }

    const passwordIsValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordIsValid) {
      return res.status(401).json({
        message: "Email ou senha inválidos"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: "1d"
      }
    );

    return res.json({ token });
  } catch (error) {
    console.error("Erro ao fazer login:", error);

    return res.status(500).json({
      message: "Erro ao fazer login"
    });
  }
});

app.get(
  "/me",
  authMiddleware,
  async (
    req: AuthenticatedRequest,
    res: Response
  ) => {
    try {
      const userId = req.userId;

      if (!userId) {
        return res.status(401).json({
          message: "Usuário não autenticado"
        });
      }

      await applyStudyPenalty(userId);

      const user =
        await queryOne<UserWithStudyGroup>(
          `
          SELECT
            users.id,
            users.email,
            users.nickname,
            users.goal,
            studies_group.continuous_study_day,
            studies_group.total_days_studied,
            studies_group.total_experience_points,
            studies_group.last_study_date,
            studies_group.last_penalty_date
          FROM users
          LEFT JOIN studies_group
            ON studies_group.user_id = users.id
          WHERE users.id = $1
          `,
          [userId]
        );

      if (!user) {
        return res.status(404).json({
          message: "Usuário não encontrado"
        });
      }

      return res.json(user);
    } catch (error) {
      console.error("Erro ao buscar usuário:", error);

      return res.status(500).json({
        message: "Erro ao buscar usuário"
      });
    }
  }
);

app.get(
  "/ranking",
  authMiddleware,
  async (
    req: AuthenticatedRequest,
    res: Response
  ) => {
    try {
      const userId = req.userId;

      if (!userId) {
        return res.status(401).json({
          message: "Usuário não autenticado"
        });
      }

      await applyStudyPenalty(userId);

      const ranking = await query<RankingUser>(
        `
        SELECT
          users.id,
          users.nickname,
          users.email,
          studies_group.total_experience_points
        FROM studies_group
        INNER JOIN users
          ON users.id = studies_group.user_id
        ORDER BY
          studies_group.total_experience_points DESC,
          studies_group.total_days_studied DESC,
          users.id ASC
        `
      );

      return res.json(ranking);
    } catch (error) {
      console.error("Erro ao buscar ranking:", error);

      return res.status(500).json({
        message: "Erro ao buscar ranking"
      });
    }
  }
);

app.patch(
  "/complete-study-day",
  authMiddleware,
  async (
    req: AuthenticatedRequest,
    res: Response
  ) => {
    try {
      const userId = req.userId;
      const { completed } = req.body;

      if (!userId) {
        return res.status(401).json({
          message: "Usuário não autenticado"
        });
      }

      if (completed !== true) {
        return res.status(400).json({
          message:
            "Envie completed: true para cumprir o dia de estudo"
        });
      }

      await applyStudyPenalty(userId);

      const result = await transaction(
        async client => {
          const studyGroupResult =
            await client.query<StudyGroupDatabase>(
              `
              SELECT
                continuous_study_day,
                total_days_studied,
                total_experience_points,
                last_study_date,
                last_penalty_date
              FROM studies_group
              WHERE user_id = $1
              FOR UPDATE
              `,
              [userId]
            );

          const studyGroup =
            studyGroupResult.rows[0];

          if (!studyGroup) {
            throw new Error(
              "STUDY_GROUP_NOT_FOUND"
            );
          }

          const todayString = getTodayString();

          if (
            studyGroup.last_study_date ===
            todayString
          ) {
            throw new Error(
              "STUDY_ALREADY_COMPLETED"
            );
          }

          let continuousStudyDay =
            studyGroup.continuous_study_day;

          if (!studyGroup.last_study_date) {
            continuousStudyDay = 1;
          } else {
            const diffDays = getDiffDays(
              studyGroup.last_study_date
            );

            if (diffDays === 1) {
              continuousStudyDay += 1;
            } else {
              continuousStudyDay = 1;
            }
          }

          const bonus =
            continuousStudyDay > 1
              ? continuousStudyDay - 1
              : 0;

          const earnedXp = 100 + bonus;

          const totalExperiencePoints =
            studyGroup.total_experience_points +
            earnedXp;

          await client.query(
            `
            UPDATE studies_group
            SET
              continuous_study_day = $1,
              total_days_studied =
                total_days_studied + 1,
              total_experience_points = $2,
              last_study_date = $3
            WHERE user_id = $4
            `,
            [
              continuousStudyDay,
              totalExperiencePoints,
              todayString,
              userId
            ]
          );

          const updatedUserResult =
            await client.query<UserWithStudyGroup>(
              `
              SELECT
                users.id,
                users.email,
                users.nickname,
                users.goal,
                studies_group.continuous_study_day,
                studies_group.total_days_studied,
                studies_group.total_experience_points,
                studies_group.last_study_date,
                studies_group.last_penalty_date
              FROM users
              INNER JOIN studies_group
                ON studies_group.user_id = users.id
              WHERE users.id = $1
              `,
              [userId]
            );

          return {
            earnedXp,
            user: updatedUserResult.rows[0]
          };
        }
      );

      return res.json({
        message: "Dia de estudo concluído",
        earnedXp: result.earnedXp,
        user: result.user
      });
    } catch (error) {
      console.error(
        "Erro ao cumprir dia de estudo:",
        error
      );

      if (
        error instanceof Error &&
        error.message === "STUDY_GROUP_NOT_FOUND"
      ) {
        return res.status(404).json({
          message:
            "Grupo de estudo não encontrado"
        });
      }

      if (
        error instanceof Error &&
        error.message ===
          "STUDY_ALREADY_COMPLETED"
      ) {
        return res.status(400).json({
          message:
            "Você já concluiu o estudo de hoje"
        });
      }

      return res.status(500).json({
        message: "Erro ao cumprir dia de estudo"
      });
    }
  }
);

async function bootstrap(): Promise<void> {
  try {
    await initDb();

    app.listen(PORT, () => {
      console.log(
        `API rodando em http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Erro ao inicializar aplicação:",
      error
    );

    process.exit(1);
  }
}

async function gracefulShutdown(
  signal: string
): Promise<void> {
  console.log(`${signal} recebido. Encerrando...`);

  await pool.end();

  process.exit(0);
}

process.on("SIGINT", () => {
  void gracefulShutdown("SIGINT");
});

process.on("SIGTERM", () => {
  void gracefulShutdown("SIGTERM");
});

void bootstrap();