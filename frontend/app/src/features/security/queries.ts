import { useQuery } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1AuthMfaFactorsFactorId,
  getApiV1AuthMfaFactors,
  postApiV1AuthMfaBackupCodes,
  postApiV1AuthMfaEnrollEmail,
  postApiV1AuthMfaEnrollEmailVerify,
  postApiV1AuthMfaEnrollRadius,
  postApiV1AuthMfaEnrollTotp,
  postApiV1AuthMfaEnrollTotpVerify,
  postApiV1AuthMfaStepup,
} from '../../api/generated';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import type {
  BackupCodesBody,
  DeleteFactorBody,
  EmailVerifyBody,
  EnrollEmailBody,
  EnrollRadiusBody,
  EnrollTotpBody,
  FactorsBody,
  StepUpBody,
  TotpVerifyBody,
} from './types';

/**
 * Security & MFA data layer (ADR-0017 batch 11.8, the `/auth/mfa`
 * self-service surface). One read hook and seven direct write functions:
 * the page owns the step-up retry-once orchestration (a captured
 * `stepup_required` 403 pauses the action, one code refreshes the window,
 * the action runs exactly once more), which mutation hooks would hide in
 * callbacks - so writes stay plain async calls through the generated
 * client + `expectOk`. Failures arrive as `ApiError` with the server's
 * own message (`MFA assertion failed`, `TOTP code invalid`, the
 * last-factor refusal) for verbatim rendering.
 */

/** `GET /api/v1/auth/mfa/factors` - your enrolled factors (captured). */
export function useFactors(): UseQueryResult<FactorsBody> {
  return useQuery({
    queryKey: queryKeys.securityFactors,
    queryFn: async () =>
      expectOk(await getApiV1AuthMfaFactors()).data as unknown as FactorsBody,
  });
}

/** `POST /api/v1/auth/mfa/enroll/totp` - enrol (or rotate) the app factor. */
export async function enrollTotp(): Promise<EnrollTotpBody> {
  return expectOk(await postApiV1AuthMfaEnrollTotp({})).data as unknown as EnrollTotpBody;
}

/** `POST /api/v1/auth/mfa/enroll/totp/verify` - prove the live code. */
export async function verifyTotpEnrol(code: string): Promise<TotpVerifyBody> {
  return expectOk(await postApiV1AuthMfaEnrollTotpVerify({ code }))
    .data as unknown as TotpVerifyBody;
}

/** `POST /api/v1/auth/mfa/backup-codes` - ten single-use codes (shown once). */
export async function generateBackupCodes(): Promise<BackupCodesBody> {
  return expectOk(await postApiV1AuthMfaBackupCodes({})).data as unknown as BackupCodesBody;
}

/** `POST /api/v1/auth/mfa/enroll/email` - send the mailbox enrolment code. */
export async function enrollEmail(): Promise<EnrollEmailBody> {
  return expectOk(await postApiV1AuthMfaEnrollEmail({})).data as unknown as EnrollEmailBody;
}

/** `POST /api/v1/auth/mfa/enroll/email/verify` - activate the e-mail factor. */
export async function verifyEmailEnrol(
  challengeId: string,
  code: string,
): Promise<EmailVerifyBody> {
  return expectOk(
    await postApiV1AuthMfaEnrollEmailVerify({ challenge_id: challengeId, code }),
  ).data as unknown as EmailVerifyBody;
}

/** `DELETE /api/v1/auth/mfa/factors/{id}` - remove one factor (fail-closed). */
export async function deleteFactor(factorId: number): Promise<DeleteFactorBody> {
  return expectOk(await deleteApiV1AuthMfaFactorsFactorId(factorId))
    .data as unknown as DeleteFactorBody;
}

/** `POST /api/v1/auth/mfa/enroll/radius` - enrol RADIUS push/OTP (or the
 * captured 503 while the `radius` settings group is unconfigured). */
export async function enrollRadius(): Promise<EnrollRadiusBody> {
  return expectOk(await postApiV1AuthMfaEnrollRadius({}))
    .data as unknown as EnrollRadiusBody;
}

/** `POST /api/v1/auth/mfa/stepup` - refresh the MFA window (captured). */
export async function stepUp(totpCode: string): Promise<StepUpBody> {
  return expectOk(await postApiV1AuthMfaStepup({ totp_code: totpCode }))
    .data as unknown as StepUpBody;
}
