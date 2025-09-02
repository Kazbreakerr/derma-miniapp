
-- app_state.sql
-- Schema to track splash/welcome/role/onboarding flags in Postgres for Telegram mini‑app users.

BEGIN;

CREATE TABLE IF NOT EXISTS app_user_state (
  tg_id BIGINT PRIMARY KEY,                           -- Telegram user id
  role TEXT CHECK (role IN ('patient','doctor')),     -- выбранная роль

  splash_seen BOOLEAN NOT NULL DEFAULT FALSE,         -- проигрывали ли splash-video
  welcome_seen BOOLEAN NOT NULL DEFAULT FALSE,        -- заходили ли на welcome-rt

  consented_at TIMESTAMPTZ,                           -- согласие с предупреждениями (warnings)
  profile_completed_at TIMESTAMPTZ,                   -- заполнен профиль
  plan_created_at TIMESTAMPTZ,                        -- создан план лечения

  patient_done BOOLEAN NOT NULL DEFAULT FALSE,        -- завершён первичный онбординг пациента
  doctor_onboarding_done BOOLEAN NOT NULL DEFAULT FALSE, -- завершён онбординг врача

  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Optional trigger to keep updated_at fresh
CREATE OR REPLACE FUNCTION _touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_app_user_state_touch'
  ) THEN
    CREATE TRIGGER trg_app_user_state_touch
    BEFORE UPDATE ON app_user_state
    FOR EACH ROW EXECUTE PROCEDURE _touch_updated_at();
  END IF;
END;
$$;

-- Mark splash as seen (idempotent)
CREATE OR REPLACE FUNCTION mark_splash_seen(p_tg_id BIGINT)
RETURNS VOID AS $$
BEGIN
  INSERT INTO app_user_state (tg_id, splash_seen, first_seen_at, last_seen_at, updated_at)
  VALUES (p_tg_id, TRUE, now(), now(), now())
  ON CONFLICT (tg_id)
  DO UPDATE SET splash_seen = TRUE, last_seen_at = now(), updated_at = now();
END;
$$ LANGUAGE plpgsql;

-- Upsert role
CREATE OR REPLACE FUNCTION upsert_role(p_tg_id BIGINT, p_role TEXT)
RETURNS VOID AS $$
BEGIN
  INSERT INTO app_user_state (tg_id, role, last_seen_at, updated_at)
  VALUES (p_tg_id, p_role, now(), now())
  ON CONFLICT (tg_id)
  DO UPDATE SET role = EXCLUDED.role, last_seen_at = now(), updated_at = now();
END;
$$ LANGUAGE plpgsql;

-- Mark patient pipeline steps
CREATE OR REPLACE FUNCTION mark_patient_step(p_tg_id BIGINT, p_step TEXT)
RETURNS VOID AS $$
BEGIN
  IF p_step = 'consent' THEN
    UPDATE app_user_state SET consented_at = now() WHERE tg_id = p_tg_id;
    IF NOT FOUND THEN INSERT INTO app_user_state(tg_id, consented_at) VALUES (p_tg_id, now()); END IF;
  ELSIF p_step = 'profile' THEN
    UPDATE app_user_state SET profile_completed_at = now() WHERE tg_id = p_tg_id;
    IF NOT FOUND THEN INSERT INTO app_user_state(tg_id, profile_completed_at) VALUES (p_tg_id, now()); END IF;
  ELSIF p_step = 'plan' THEN
    UPDATE app_user_state SET plan_created_at = now() WHERE tg_id = p_tg_id;
    IF NOT FOUND THEN INSERT INTO app_user_state(tg_id, plan_created_at) VALUES (p_tg_id, now()); END IF;
  ELSIF p_step = 'patient_done' THEN
    UPDATE app_user_state SET patient_done = TRUE WHERE tg_id = p_tg_id;
    IF NOT FOUND THEN INSERT INTO app_user_state(tg_id, patient_done) VALUES (p_tg_id, TRUE); END IF;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Mark doctor onboarding completion
CREATE OR REPLACE FUNCTION mark_doctor_done(p_tg_id BIGINT)
RETURNS VOID AS $$
BEGIN
  INSERT INTO app_user_state (tg_id, doctor_onboarding_done, last_seen_at, updated_at)
  VALUES (p_tg_id, TRUE, now(), now())
  ON CONFLICT (tg_id)
  DO UPDATE SET doctor_onboarding_done = TRUE, last_seen_at = now(), updated_at = now();
END;
$$ LANGUAGE plpgsql;

-- Reset user app state to "first time"
CREATE OR REPLACE FUNCTION reset_user_app_state(p_tg_id BIGINT)
RETURNS VOID AS $$
BEGIN
  UPDATE app_user_state
     SET splash_seen = FALSE,
         welcome_seen = FALSE,
         consented_at = NULL,
         profile_completed_at = NULL,
         plan_created_at = NULL,
         patient_done = FALSE,
         doctor_onboarding_done = FALSE,
         last_seen_at = now(),
         updated_at = now()
   WHERE tg_id = p_tg_id;

  IF NOT FOUND THEN
     INSERT INTO app_user_state (tg_id) VALUES (p_tg_id);
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Utility view to quickly see who будет считать "первым входом"
CREATE OR REPLACE VIEW v_first_time_users AS
SELECT
  tg_id,
  COALESCE(NOT splash_seen, TRUE) AS is_first_time,
  role, patient_done, doctor_onboarding_done,
  consented_at, profile_completed_at, plan_created_at,
  first_seen_at, last_seen_at, updated_at
FROM app_user_state;

COMMIT;

-- ===================
-- USAGE EXAMPLES
-- ===================
-- 1) Отметить, что пользователь увидел splash:
--    SELECT mark_splash_seen(123456789);

-- 2) Сохранить выбранную роль:
--    SELECT upsert_role(123456789, 'patient'); -- или 'doctor'

-- 3) Помечать шаги пациента:
--    SELECT mark_patient_step(123456789, 'consent');
--    SELECT mark_patient_step(123456789, 'profile');
--    SELECT mark_patient_step(123456789, 'plan');
--    SELECT mark_patient_step(123456789, 'patient_done');

-- 4) Завершить онбординг врача:
--    SELECT mark_doctor_done(123456789);

-- 5) Обнулить состояние для пользователя (вернуть к "первому входу"):
--    SELECT reset_user_app_state(123456789);

-- 6) Посмотреть, кого система сочтёт "первым входом":
--    SELECT * FROM v_first_time_users WHERE is_first_time;
