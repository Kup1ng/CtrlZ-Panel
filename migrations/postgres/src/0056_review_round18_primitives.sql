-- P1 auth review round 18, area crypto primitives (finding primitives-r18-2, D64 otp-aad-row).
--
-- The sealed delivery text of an OTP challenge (otp_challenges.delivery_ct) was bound to the phone
-- and the purpose of its row and to nothing else, so a role that can write the table could copy an
-- old delivery_ct into a fresh row of the same phone: the sender then delivered the old code while
-- the row checked the new hash, and repeating it kept the victim out of SMS sign-in. The row has no
-- id of its own when the text is sealed (the insert assigns it), so the seal is now bound to the
-- keyed hash of the row's own code, which the issuer computes before the insert (internal/sms
-- payload.go, keyring.DigestContext).
--
-- The sender has to read that hash back with the row to open the text. It already reads the code in
-- the clear (it sends it), so the hash tells it nothing it could not compute; it holds no auth_mac
-- key, so it cannot use the hash to test guesses for a code it did not see. This grant is the whole
-- change in the database: auth_otp_issue stores p_code_hash as before and is not touched here.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

GRANT SELECT (code_hash) ON ctrlz.otp_challenges TO ctrlz_worker;
