-- Questions 17 and 19 of the owner (2026-11-24) and the SMS half of D67.
--
-- Question 17: a Remember me session past its idle limit that a refresh token can still revive is live. The live
-- rule is one SQL text in internal/store (qSessionLive) and asks the refresh tokens of the session, so the index
-- below serves that lookup: by tenant and session, for the tokens that can still be used.
--
-- D67 (the owner: "we are not allowed to send a link by SMS, the user copies it and gives it to whomever"): an
-- invite is never sent by SMS, so the outbox kind `invite`, its two templates and the rows it left go. The outbox
-- needs a retriable kind once `invite` leaves, and the notice of question 19 is that kind.
--
-- Question 19: adding a passkey or replacing the recovery codes now also sends one SMS to the verified phone of
-- the account. ctrlz_fn.tenant_notice_sms queues it, and it takes neither a phone nor a text from its caller: it
-- reads the kind of the notice, and the verified phone and locale of the user, under the tenant of the setting.
-- The row of sms_outbox has the id of the notice, so one notice is one message whatever is called twice, and no
-- sealed value: a notice carries nothing a gateway has to be told but its template (the CHECK below).
--
-- The daily cap is counted per kind: over the audit rows of the action that made this notice (passkey.add for a
-- passkey, recovery.regenerate for the codes), so a holder of the session cannot spend the messages of one kind
-- to silence the other (review dec-c-r1-6). The caller's own row is
-- one of them (the route writes it first), so the messages before this one are the count less one.
-- ctrlz.cap_reached compares, as for every cap. The function is owned by ctrlz_scoped (0055), so it meets
-- tenant_isolation on every tenant table it reads, and the INSERT into sms_outbox, a global table, is the one
-- thing it can do beyond them: INSERT only, no SELECT, no UPDATE.
--
-- The rows of kind `invite` that are waiting are deleted too: a worker that holds one finds no row to finish and
-- logs it, as for a row the sweep removed. Nothing is deployed. sms_deliveries keeps its history: it holds no
-- phone and no text.
--
-- A new file and not an edit of an applied one (rule applied-migrations-are-frozen).

-- +goose Up

SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';

CREATE INDEX refresh_tokens_session_idx ON ctrlz.refresh_tokens (tenant_id, session_id)
  WHERE revoked_at IS NULL AND rotated_at IS NULL;

-- The invite SMS. The kind CHECK of 0011 is unnamed, so it has its default name.
DELETE FROM ctrlz.sms_outbox WHERE kind = 'invite';
ALTER TABLE ctrlz.sms_outbox DROP CONSTRAINT sms_outbox_kind_check;
ALTER TABLE ctrlz.sms_outbox
  ADD CONSTRAINT sms_outbox_kind_check CHECK (kind IN ('notice', 'test')),
  ADD CONSTRAINT sms_outbox_notice_bare CHECK (kind <> 'notice'
    OR (params_ct IS NULL AND gateway_id IS NULL AND template_key IN ('notice_passkey', 'notice_recovery')));

DELETE FROM ctrlz.sms_provider_templates WHERE key = 'invite';
DELETE FROM ctrlz.sms_templates WHERE key = 'invite';

-- The two notice bodies, one billed part each (spec 9.4): 61 and 62 UCS-2 units in Persian, 87 and 85 GSM-7
-- units in English.
INSERT INTO ctrlz.sms_templates (key, locale, body) VALUES
  ('notice_passkey', 'fa', 'Passkey تازه برای Ctrl Z ثبت شد. شما نبودید؟ رمز را عوض کنید.'),
  ('notice_passkey', 'en', 'Ctrl Z: a passkey was added to your account. If this was not you, change your password.'),
  ('notice_recovery', 'fa', 'کدهای بازیابی حساب Ctrl Z عوض شد. شما نبودید؟ رمز را عوض کنید.'),
  ('notice_recovery', 'en', 'Ctrl Z: your recovery codes were replaced. If this was not you, change your password.')
ON CONFLICT (key, locale) DO NOTHING;

-- What the function reads and writes, and no more. 0061 grants the same three columns of users (a grant twice is
-- the same grant).
GRANT SELECT (phone_e164, phone_verified_at, locale) ON ctrlz.users TO ctrlz_scoped;
GRANT SELECT (tenant_id, id, kind) ON ctrlz.notifications TO ctrlz_scoped;
GRANT SELECT (tenant_id, action, at) ON ctrlz.tenant_audit_log TO ctrlz_scoped;
GRANT INSERT (id, kind, phone_e164, template_key, locale) ON ctrlz.sms_outbox TO ctrlz_scoped;
GRANT EXECUTE ON FUNCTION ctrlz.cap_reached(numeric, numeric) TO ctrlz_scoped;

SET ROLE ctrlz_auth;
GRANT USAGE, CREATE ON SCHEMA ctrlz_fn TO ctrlz_scoped;
RESET ROLE;

SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.tenant_notice_sms(p_user_id uuid, p_notice_id uuid, p_cap integer)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant   uuid := ctrlz.current_tenant_id();
  v_template text;
  v_phone    text;
  v_locale   text;
  v_n        bigint;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL OR p_notice_id IS NULL OR p_cap IS NULL THEN
    RETURN false;
  END IF;

  -- The kind of the notice names the template; any other kind of notice has no SMS.
  SELECT CASE n.kind WHEN 'passkey_added' THEN 'notice_passkey'
                     WHEN 'recovery_codes_regenerated' THEN 'notice_recovery' END
    INTO v_template
    FROM ctrlz.notifications n
   WHERE n.tenant_id = v_tenant AND n.id = p_notice_id;
  IF v_template IS NULL THEN
    RETURN false;
  END IF;

  -- Only a phone the account proved is told.
  SELECT u.phone_e164, u.locale INTO v_phone, v_locale
    FROM ctrlz.users u
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.phone_verified_at IS NOT NULL;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  -- The audit row of the change that made this notice is already written, so it is one of the rows counted.
  SELECT pg_catalog.count(*) INTO v_n
    FROM ctrlz.tenant_audit_log a
   WHERE a.tenant_id = v_tenant
     AND a.action = CASE v_template WHEN 'notice_passkey' THEN 'passkey.add' ELSE 'recovery.regenerate' END
     AND a.at > pg_catalog.now() - interval '24 hours';
  IF ctrlz.cap_reached(v_n - 1, p_cap) THEN
    RETURN false;
  END IF;

  -- No conflict target: a target would need SELECT on the table. The id is the notice's, so a second call for
  -- the same notice queues nothing.
  INSERT INTO ctrlz.sms_outbox (id, kind, phone_e164, template_key, locale)
  VALUES (p_notice_id, 'notice', v_phone, v_template, v_locale)
  ON CONFLICT DO NOTHING;
  RETURN FOUND;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.tenant_notice_sms(uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.tenant_notice_sms(uuid, uuid, integer) TO ctrlz_tenant;
RESET ROLE;

SET ROLE ctrlz_auth;
REVOKE USAGE, CREATE ON SCHEMA ctrlz_fn FROM ctrlz_scoped;
RESET ROLE;
