import { z } from "zod";
import { ArgPathError, parseArgPath } from "./argpath.js";
import { compilePolicyRegex } from "./regex.js";

const name = z.string().min(1);

const HostnameArgSchema = z.strictObject({
  type: z.literal("hostname"),
  allow: z.array(name).min(1),
  deny_ip_literals: z.boolean().default(true),
  required: z.boolean().default(true),
});

const UrlArgSchema = z.strictObject({
  type: z.literal("url"),
  schemes: z.array(name).min(1),
  hosts: z.array(name).min(1),
  deny_private_ranges: z.boolean().default(true),
  deny_userinfo: z.boolean().default(true),
  required: z.boolean().default(true),
});

const PathArgSchema = z.strictObject({
  type: z.literal("path"),
  within: z.array(name).min(1),
  deny: z.array(name).default([]),
  resolve_symlinks: z.boolean().default(true),
  required: z.boolean().default(true),
});

const StringArgSchema = z.strictObject({
  type: z.literal("string"),
  allow: z.array(name).optional(),
  deny: z.array(name).optional(),
  min_length: z.number().int().nonnegative().optional(),
  max_length: z.number().int().nonnegative().optional(),
  pattern: z.string().min(1).max(256).optional(),
  required: z.boolean().default(true),
});

const NumberArgSchema = z.strictObject({
  type: z.literal("number"),
  minimum: z.number().optional(),
  maximum: z.number().optional(),
  integer: z.boolean().default(false),
  required: z.boolean().default(true),
});

export const ArgRuleSchema = z.discriminatedUnion("type", [
  HostnameArgSchema,
  UrlArgSchema,
  PathArgSchema,
  StringArgSchema,
  NumberArgSchema,
]);

const ToolRuleSchema = z.strictObject({
  decision: z.enum(["allow", "deny"]),
  reason: z.string().min(1).optional(),
  args: z.record(z.string(), ArgRuleSchema).optional(),
});

const ServerSchema = z.strictObject({
  tools: z.record(name, ToolRuleSchema),
});

const SecretSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/u),
  regex: z.string().min(1).max(256),
});

const LaunchEntrySchema = z.strictObject({
  command: name,
  flags: z.array(name).min(1),
});

const DefaultsSchema = z
  .strictObject({
    tool: z.enum(["allow", "deny"]).default("deny"),
    unknown_args: z.enum(["allow", "deny"]).default("deny"),
    method: z.enum(["allow", "deny"]).default("allow"),
  })
  .default({ tool: "deny", unknown_args: "deny", method: "allow" });

const LimitsSchema = z
  .strictObject({
    max_message_bytes: z
      .number()
      .int()
      .positive()
      .max(32 * 1024 * 1024)
      .default(1_048_576),
  })
  .default({ max_message_bytes: 1_048_576 });

const LogSchema = z
  .strictObject({
    path: z.string().min(1).default("~/.argguard/decisions.jsonl"),
    store_args: z.enum(["none", "hashed", "redacted"]).default("hashed"),
    redact_keys: z
      .array(z.string().min(1))
      .default(["password", "token", "secret", "authorization", "api_key"]),
  })
  .default({
    path: "~/.argguard/decisions.jsonl",
    store_args: "hashed",
    redact_keys: ["password", "token", "secret", "authorization", "api_key"],
  });

export const PolicySchema = z
  .strictObject({
    version: z.literal(1),
    mode: z.enum(["enforce", "monitor"]),
    defaults: DefaultsSchema,
    methods: z.record(name, z.enum(["allow", "deny"])).optional(),
    limits: LimitsSchema,
    log: LogSchema,
    secrets: z.array(SecretSchema).default([]),
    servers: z.record(name, ServerSchema).default({}),
    launch: z
      .strictObject({
        deny_inline_code: z.array(LaunchEntrySchema).min(1),
      })
      .optional(),
  })
  .superRefine((policy, ctx) => {
    for (const [serverName, server] of Object.entries(policy.servers)) {
      for (const [toolName, tool] of Object.entries(server.tools)) {
        if (!tool.args) continue;
        for (const [argPath, rule] of Object.entries(tool.args)) {
          try {
            parseArgPath(argPath);
          } catch (error) {
            const message = error instanceof ArgPathError ? error.message : "invalid argument path";
            ctx.addIssue({
              code: "custom",
              message,
              path: ["servers", serverName, "tools", toolName, "args", argPath],
            });
          }
          if (rule.type === "string" && rule.pattern) {
            try {
              compilePolicyRegex(rule.pattern, `${toolName}.${argPath}`);
            } catch (error) {
              ctx.addIssue({
                code: "custom",
                message: error instanceof Error ? error.message : "invalid pattern",
                path: ["servers", serverName, "tools", toolName, "args", argPath, "pattern"],
              });
            }
          }
          if (
            rule.type === "number" &&
            rule.minimum !== undefined &&
            rule.maximum !== undefined &&
            rule.minimum > rule.maximum
          ) {
            ctx.addIssue({
              code: "custom",
              message: "minimum is greater than maximum",
              path: ["servers", serverName, "tools", toolName, "args", argPath],
            });
          }
        }
      }
    }
    for (const secret of policy.secrets) {
      try {
        compilePolicyRegex(secret.regex, secret.id);
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          message: error instanceof Error ? error.message : "invalid secret regex",
          path: ["secrets", secret.id],
        });
      }
    }
  });

export type Policy = z.output<typeof PolicySchema>;
export type ArgRule = z.output<typeof ArgRuleSchema>;
export type HostnameArg = z.output<typeof HostnameArgSchema>;
export type UrlArg = z.output<typeof UrlArgSchema>;
export type PathArg = z.output<typeof PathArgSchema>;
export type StringArg = z.output<typeof StringArgSchema>;
export type NumberArg = z.output<typeof NumberArgSchema>;
export type ToolRule = z.output<typeof ToolRuleSchema>;
export type LaunchRule = z.output<typeof LaunchEntrySchema>;
