import "dotenv/config";

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

const SALT_ROUNDS =
  Number(process.env.BCRYPT_SALT_ROUNDS) || 10;

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
  continuous_study_day: number | string;
  total_days_studied: number | string;
  total_experience_points: number | string;
  last_study_date: string | Date | null;
  last_penalty_date: string | Date | null;
}

interface UserWithStudyGroup {
  id: number;
  email: string;
  nickname: string | null;
  goal: number;
  continuous_study_day: number | null;
  total_days_studied: number | null;
  total_experience_points: number | null;
  last_study_date: string | Date | null;
  last_penalty_date: string | Date | null;
}

interface RankingUser {
  id: number;
  nickname: string | null;
  email: string;
  total_experience_points: number;
}

/**
 * Retorna a data atual no formato YYYY-MM-DD.
 *
 * O timezone é definido explicitamente para evitar que o servidor
 * do Render, que normalmente trabalha em UTC, considere o próximo
 * ou o dia anterior no Brasil.
 */
function getTodayString(): string {
  const formatter = new Intl.DateTimeFormat(
    "en-CA",
    {
      timeZone: "America/Sao_Paulo",
      year: "numeric",
      month: "2-digit",
      day: "2-digit"
    }
  );

  return formatter.format(new Date());
}

/**
 * Converte uma data recebida do PostgreSQL para YYYY-MM-DD.
 *
 * Aceita:
 * - "2026-08-01"
 * - "2026-08-01T00:00:00.000Z"
 * - objetos Date
 */
function normalizeDateString(
  dateValue: string | Date
): string {
  if (dateValue instanceof Date) {
    if (Number.isNaN(dateValue.getTime())) {
      throw new Error(
        `Data inválida recebida: ${String(dateValue)}`
      );
    }

    return dateValue.toISOString().slice(0, 10);
  }

  const value = String(dateValue).trim();

  const dateMatch = value.match(
    /^(\d{4}-\d{2}-\d{2})/
  );

  if (!dateMatch) {
    throw new Error(
      `Formato de data inválido: ${value}`
    );
  }

  return dateMatch[1];
}

/**
 * Converte valores numéricos vindos do banco.
 *
 * Essa validação impede que NaN seja enviado para o PostgreSQL.
 */
function parseDatabaseNumber(
  value: number | string,
  fieldName: string
): number {
  const parsedValue = Number(value);

  if (!Number.isFinite(parsedValue)) {
    throw new Error(
      `${fieldName} possui um valor inválido: ${String(
        value
      )}`
    );
  }

  return parsedValue;
}

/**
 * Calcula quantos dias existem entre a data informada e hoje.
 */
function getDiffDays(
  dateValue: string | Date
): number {
  const todayString = getTodayString();

  const normalizedDate =
    normalizeDateString(dateValue);

  const todayParts = todayString
    .split("-")
    .map(Number);

  const dateParts = normalizedDate
    .split("-")
    .map(Number);

  const [todayYear, todayMonth, todayDay] =
    todayParts;

  const [dateYear, dateMonth, dateDay] =
    dateParts;

  const todayTimestamp = Date.UTC(
    todayYear,
    todayMonth - 1,
    todayDay
  );

  const dateTimestamp = Date.UTC(
    dateYear,
    dateMonth - 1,
    dateDay
  );

  if (
    !Number.isFinite(todayTimestamp) ||
    !Number.isFinite(dateTimestamp)
  ) {
    throw new Error(
      `Não foi possível calcular a diferença entre ${normalizedDate} e ${todayString}`
    );
  }

  return Math.floor(
    (todayTimestamp - dateTimestamp) /
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

  const [tokenType, token] =
    authHeader.split(" ");

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

/**
 * Aplica a penalidade por ausência.
 *
 * Regras:
 * - 1 dia sem estudar: não perde pontos.
 * - 2 dias sem estudar: perde 50 pontos.
 * - Cada novo dia sem estudar: perde mais 50 pontos.
 * - A pontuação nunca fica negativa.
 * - A penalidade é aplicada somente uma vez por dia.
 */
async function applyStudyPenalty(
  userId: number
): Promise<void> {
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

  if (!studyGroup) {
    return;
  }

  if (!studyGroup.last_study_date) {
    return;
  }

  const todayString = getTodayString();

  const normalizedLastStudyDate =
    normalizeDateString(
      studyGroup.last_study_date
    );

  const normalizedLastPenaltyDate =
    studyGroup.last_penalty_date
      ? normalizeDateString(
          studyGroup.last_penalty_date
        )
      : null;

  /*
   * Impede que a penalidade seja aplicada mais
   * de uma vez no mesmo dia.
   */
  if (
    normalizedLastPenaltyDate === todayString
  ) {
    return;
  }

  const daysWithoutStudy = getDiffDays(
    normalizedLastStudyDate
  );

  /*
   * O usuário pode ficar um dia sem estudar
   * sem perder pontos.
   */
  if (daysWithoutStudy < 2) {
    return;
  }

  let daysToPenalize = 0;

  if (normalizedLastPenaltyDate) {
    /*
     * Se uma penalidade já foi aplicada,
     * calcula quantos novos dias passaram.
     */
    daysToPenalize = getDiffDays(
      normalizedLastPenaltyDate
    );
  } else {
    /*
     * No primeiro cálculo, desconsidera
     * o primeiro dia de ausência.
     *
     * 2 dias sem estudo = 1 penalidade.
     * 3 dias sem estudo = 2 penalidades.
     */
    daysToPenalize = daysWithoutStudy - 1;
  }

  if (daysToPenalize <= 0) {
    return;
  }

  const currentXp = parseDatabaseNumber(
    studyGroup.total_experience_points,
    "total_experience_points"
  );

  const penalty = daysToPenalize * 50;

  const newXp = Math.max(
    0,
    currentXp - penalty
  );

  if (!Number.isFinite(newXp)) {
    throw new Error(
      `Erro ao calcular o novo XP do usuário ${userId}`
    );
  }

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

app.get("/", (_req, res) => {
  return res.json({
    message: "Projeto Blue API",
    status: "online"
  });
});

app.post(
  "/create-user",
  async (req, res) => {
    try {
      const {
        email,
        nickname,
        password
      } = req.body;

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

      if (
        typeof nickname !== "undefined" &&
        typeof nickname !== "string"
      ) {
        return res.status(400).json({
          message: "Nickname inválido"
        });
      }

      const normalizedEmail = email
        .trim()
        .toLowerCase();

      const normalizedNickname =
        typeof nickname === "string" &&
        nickname.trim().length > 0
          ? nickname.trim()
          : null;

      const hashedPassword =
        await bcrypt.hash(
          password,
          SALT_ROUNDS
        );

      const createdUser = await transaction(
        async client => {
          const userResult =
            await client.query<{
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
                normalizedNickname,
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
            [
              user.id,
              0,
              0,
              0,
              null,
              null
            ]
          );

          return user;
        }
      );

      return res
        .status(201)
        .json(createdUser);
    } catch (error: unknown) {
      console.error(
        "Erro ao criar usuário:",
        error
      );

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
  }
);

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

    const user =
      await queryOne<UserDatabase>(
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

    const passwordIsValid =
      await bcrypt.compare(
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
    console.error(
      "Erro ao fazer login:",
      error
    );

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
      console.error(
        "Erro ao buscar usuário:",
        error
      );

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

      /*
       * Mantém o comportamento original:
       * aplica a penalidade somente no usuário
       * autenticado antes de exibir o ranking.
       */
      await applyStudyPenalty(userId);

      const ranking =
        await query<RankingUser>(
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
      console.error(
        "Erro ao buscar ranking:",
        error
      );

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

          const todayString =
            getTodayString();

          const normalizedLastStudyDate =
            studyGroup.last_study_date
              ? normalizeDateString(
                  studyGroup.last_study_date
                )
              : null;

          if (
            normalizedLastStudyDate ===
            todayString
          ) {
            throw new Error(
              "STUDY_ALREADY_COMPLETED"
            );
          }

          const currentContinuousStudyDay =
            parseDatabaseNumber(
              studyGroup.continuous_study_day,
              "continuous_study_day"
            );

          const currentTotalXp =
            parseDatabaseNumber(
              studyGroup.total_experience_points,
              "total_experience_points"
            );

          let continuousStudyDay = 1;

          if (normalizedLastStudyDate) {
            const diffDays = getDiffDays(
              normalizedLastStudyDate
            );

            /*
             * Se estudou ontem, aumenta a sequência.
             *
             * Se passou mais de um dia, inicia
             * uma nova sequência.
             */
            if (diffDays === 1) {
              continuousStudyDay =
                currentContinuousStudyDay + 1;
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
            currentTotalXp + earnedXp;

          if (
            !Number.isFinite(
              totalExperiencePoints
            )
          ) {
            throw new Error(
              "INVALID_EXPERIENCE_POINTS"
            );
          }

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
        error.message ===
          "STUDY_GROUP_NOT_FOUND"
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

      if (
        error instanceof Error &&
        error.message ===
          "INVALID_EXPERIENCE_POINTS"
      ) {
        return res.status(500).json({
          message:
            "A pontuação do usuário possui um valor inválido"
        });
      }

      return res.status(500).json({
        message:
          "Erro ao cumprir dia de estudo"
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
  console.log(
    `${signal} recebido. Encerrando...`
  );

  try {
    await pool.end();

    console.log(
      "Conexão com o banco encerrada."
    );

    process.exit(0);
  } catch (error) {
    console.error(
      "Erro ao encerrar conexão com o banco:",
      error
    );

    process.exit(1);
  }
}

process.on("SIGINT", () => {
  void gracefulShutdown("SIGINT");
});

process.on("SIGTERM", () => {
  void gracefulShutdown("SIGTERM");
});

void bootstrap();