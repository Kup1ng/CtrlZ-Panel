-- P1 auth review round 11, SMS area (sms-r11-2, sms-r11-5; owner decision D58, 2026-11-14).
--
-- The three Persian OTP bodies seeded by 0011 are 76, 83 and 78 characters with a 6-digit code.
-- A Persian message holds 70 UCS-2 units in one part, and both providers bill each part, so every
-- code cost two parts and the money cap and the price-per-message note were wrong by a factor of
-- two for the three highest-volume templates. The owner cut the bodies to one part (at most 64
-- units with the code, so a small edit stays inside it). The code lives 5 minutes
-- (auth_otp_issue, keyring.LifeOTP), so the words "5 minutes" stay true.
--
-- Each row is changed only WHILE IT STILL HOLDS the seed text of 0011, so a body an operator
-- edited on the SMS page is never overwritten, and running the file again changes nothing. 0011
-- is applied and frozen (applied.sum), so this is a new file. The provider template mapping
-- (sms_provider_templates) holds a provider's id and its parameter names, not the body, so
-- nothing else reads the old text. An operator whose provider approved the old copy asks the
-- provider to approve the new one (spec 9.4).
--
-- internal/sms TestOTPBodiesFitOnePart renders every OTP body with a 6-digit code and refuses one
-- above 64 UCS-2 units (fa) or 160 GSM-7 characters (en), and TestTheSeedsAreTheMigrationsBodies
-- ties this file to the seed table and to 0011.

-- +goose Up

UPDATE ctrlz.sms_templates SET body = 'کد تایید Ctrl Z: {code}. اعتبار ۵ دقیقه؛ آن را به کسی ندهید.'
WHERE key = 'otp' AND locale = 'fa' AND body = 'کد تایید Ctrl Z: {code}. این کد ۵ دقیقه اعتبار دارد و نباید به کسی داده شود.';

UPDATE ctrlz.sms_templates SET body = 'کد بازیابی رمز Ctrl Z: {code}. اگر شما نخواستید، نادیده بگیرید.'
WHERE key = 'otp_reset' AND locale = 'fa' AND body = 'کد بازیابی رمز Ctrl Z: {code}. اگر شما درخواست نداده‌اید این پیام را نادیده بگیرید.';

UPDATE ctrlz.sms_templates SET body = 'کد تغییر شماره Ctrl Z: {code}. اگر شما نبودید، رمز را عوض کنید.'
WHERE key = 'otp_phone' AND locale = 'fa' AND body = 'کد تغییر شماره Ctrl Z: {code}. اگر شما درخواست نداده‌اید رمز حساب را عوض کنید.';
