import { z } from 'zod';

/**
 * ADR-0016 batch 11.7 - create-user form (openapi `POST /users`): mirrors
 * the contract's field limits (username max 64, email max 255, display_name
 * max 128, password max 200) and the server's captured policy refusal
 * (`details.min_length: 14` - "Password must be at least 14 characters
 * (NIST: length over complexity)"). An empty password means "let the server
 * generate a strong one" (captured: `generated_password` shown once).
 * The server validates always (ADR-0006); messages are i18n-mapped here.
 */
export const usersCreateSchema = z.object({
  username: z.string().trim().min(1).max(64),
  email: z.string().trim().max(255).optional(),
  display_name: z.string().trim().max(128).optional(),
  password: z.union([z.string().min(14).max(200), z.literal('')]).optional(),
});

export type UsersCreateFormValues = z.infer<typeof usersCreateSchema>;
