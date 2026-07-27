import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { initDb } from "./database";

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

function getTodayString() {
  return new Date().toISOString().split("T")[0];
}

function getDiffDays(dateString: string) {
  const today = new Date(getTodayString());
  const date = new Date(dateString);

  return Math.floor(
    (today.getTime() - date.getTime()) / (1000 * 60 * 60 * 24)
  );
}

function authMiddleware(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Token não informado" });
  }

  const [, token] = authHeader.split(" ");

  if (!token) {
    return res.status(401).json({ message: "Token inválido" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: number };
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido ou expirado" });
  }
}

async function bootstrap() {
  const db = await initDb();

  async function applyStudyPenalty(userId: number) {
    const studyGroup = await db.get(
      `
      SELECT
        continuous_study_day,
        total_experience_points,
        last_study_date,
        last_penalty_date
      FROM studies_group
      WHERE user_id = ?
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

    const daysWithoutStudy = getDiffDays(studyGroup.last_study_date);

    if (daysWithoutStudy < 2) {
      return;
    }

    const lastPenaltyBaseDate =
      studyGroup.last_penalty_date || studyGroup.last_study_date;

    const penaltyDiffDays = getDiffDays(lastPenaltyBaseDate);

    if (penaltyDiffDays <= 0) {
      return;
    }

    const penalty = penaltyDiffDays * 50;

    const newXp = Math.max(
      0,
      studyGroup.total_experience_points - penalty
    );

    await db.run(
      `
      UPDATE studies_group
      SET
        continuous_study_day = 0,
        total_experience_points = ?,
        last_penalty_date = ?
      WHERE user_id = ?
      `,
      [newXp, todayString, userId]
    );
  }

  app.post("/create-user", async (req, res) => {
    try {
      const { email, nickname, password } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email é obrigatório" });
      }

      if (!password) {
        return res.status(400).json({ message: "Senha é obrigatória" });
      }

      const userAlreadyExists = await db.get(
        `SELECT id FROM users WHERE email = ?`,
        [email]
      );

      if (userAlreadyExists) {
        return res.status(400).json({ message: "Usuário já existe" });
      }

      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

      const result = await db.run(
        `
        INSERT INTO users (
          email,
          nickname,
          password,
          goal
        )
        VALUES (?, ?, ?, ?)
        `,
        [email, nickname ?? null, hashedPassword, 100]
      );

      const userId = result.lastID;

      await db.run(
        `
        INSERT INTO studies_group (
          user_id,
          continuous_study_day,
          total_days_studied,
          total_experience_points,
          last_study_date,
          last_penalty_date
        )
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [userId, 0, 0, 0, null, null]
      );

      return res.status(201).json({
        id: userId,
        email,
        nickname,
        goal: 100
      });
    } catch (error) {
      console.log(error)
      return res.status(500).json({
        message: "Erro ao criar usuário",
        error
      });
    }
  });

  app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email é obrigatório" });
      }

      if (!password) {
        return res.status(400).json({ message: "Senha é obrigatória" });
      }

      const user = await db.get(
        `
        SELECT id, email, password
        FROM users
        WHERE email = ?
        `,
        [email]
      );

      if (!user) {
        return res.status(401).json({ message: "Email ou senha inválidos" });
      }

      const passwordIsValid = await bcrypt.compare(password, user.password);

      if (!passwordIsValid) {
        return res.status(401).json({ message: "Email ou senha inválidos" });
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
      return res.status(500).json({
        message: "Erro ao fazer login",
        error
      });
    }
  });

  app.get("/me", authMiddleware, async (req: any, res) => {
    try {
      await applyStudyPenalty(req.userId);

      const user = await db.get(
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
        LEFT JOIN studies_group ON studies_group.user_id = users.id
        WHERE users.id = ?
        `,
        [req.userId]
      );

      if (!user) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      return res.json({
        ...user
      });
    } catch (error) {
      return res.status(500).json({
        message: "Erro ao buscar usuário",
        error
      });
    }
  });

  app.get("/ranking", authMiddleware, async (req: any, res) => {
    try {
      await applyStudyPenalty(req.userId);

      const ranking = await db.all(`
        SELECT
          users.id,
          users.nickname,
          users.email,
          studies_group.total_experience_points
        FROM studies_group
        INNER JOIN users ON users.id = studies_group.user_id
        ORDER BY studies_group.total_experience_points DESC
      `);

      return res.json(ranking);
    } catch (error) {
      return res.status(500).json({
        message: "Erro ao buscar ranking",
        error
      });
    }
  });

  app.patch("/complete-study-day", authMiddleware, async (req: any, res) => {
    try {
      const { completed } = req.body;

      if (!completed) {
        return res.status(400).json({
          message: "Envie completed: true para cumprir o dia de estudo"
        });
      }

      await applyStudyPenalty(req.userId);

      const studyGroup = await db.get(
        `
        SELECT
          continuous_study_day,
          total_days_studied,
          total_experience_points,
          last_study_date
        FROM studies_group
        WHERE user_id = ?
        `,
        [req.userId]
      );

      if (!studyGroup) {
        return res.status(404).json({
          message: "Grupo de estudo não encontrado"
        });
      }

      const todayString = getTodayString();

      if (studyGroup.last_study_date === todayString) {
        return res.status(400).json({
          message: "Você já concluiu o estudo de hoje"
        });
      }

      let continuousStudyDay = studyGroup.continuous_study_day;

      if (!studyGroup.last_study_date) {
        continuousStudyDay = 1;
      } else {
        const diffDays = getDiffDays(studyGroup.last_study_date);

        if (diffDays === 1) {
          continuousStudyDay += 1;
        } else {
          continuousStudyDay = 1;
        }
      }

      const bonus = continuousStudyDay > 1 ? continuousStudyDay - 1 : 0;
      const earnedXp = 100 + bonus;

      const totalExperiencePoints =
        studyGroup.total_experience_points + earnedXp;

      await db.run(
        `
        UPDATE studies_group
        SET
          continuous_study_day = ?,
          total_days_studied = total_days_studied + 1,
          total_experience_points = ?,
          last_study_date = ?
        WHERE user_id = ?
        `,
        [
          continuousStudyDay,
          totalExperiencePoints,
          todayString,
          req.userId
        ]
      );

      const updatedUser = await db.get(
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
        INNER JOIN studies_group ON studies_group.user_id = users.id
        WHERE users.id = ?
        `,
        [req.userId]
      );

      return res.json({
        message: "Dia de estudo concluído",
        earnedXp,
        user: updatedUser
      });
    } catch (error) {
      return res.status(500).json({
        message: "Erro ao cumprir dia de estudo",
        error
      });
    }
  });

  app.listen(PORT, () => {
    console.log(`API rodando em http://localhost:${PORT}`);
  });
}

bootstrap();