import { createHash } from 'node:crypto';

import type { CallToolRequestParams, Tool } from '@modelcontextprotocol/server';

import { canonicalReceiptJson, type ReceiptIdentityEvidence } from '../audit/receipt.js';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const FORBIDDEN_FIELD = /(?:api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token)/i;
const MAX_PROFILES = 100;
const MAX_FIELDS = 64;
const MAX_STRING_LENGTH = 512;
const MAX_LIST_ITEMS = 100;
const MAX_INPUT_SCHEMA_BYTES = 65_536;
const MAX_INPUT_SCHEMA_DEPTH = 32;
const MAX_INPUT_SCHEMA_NODES = 10_000;

export type SafeIdentityScalar =
  | Readonly<{ type: 'string'; value: string }>
  | Readonly<{ type: 'enum'; value: string }>
  | Readonly<{ type: 'integer'; value: number }>
  | Readonly<{ type: 'boolean'; value: boolean }>
  | Readonly<{ type: 'null' }>;

export type SafeIdentityValue = SafeIdentityScalar | Readonly<{
  type: 'ordered_list';
  items: readonly SafeIdentityScalar[];
}>;

export type SafeIdentityClaim = Readonly<{
  name: string;
  value: SafeIdentityValue;
}>;

export type McpIdentityApprovalView = Readonly<{
  assurance: 'structural_only' | 'adapter_scoped' | 'adapter_action_exact';
  parameterCoverage: 'none' | 'declared_subset' | 'complete_action_parameters';
  profileId?: string;
  profileVersion?: number;
  profileStatus?: 'projected' | 'rejected';
  safeClaims: readonly SafeIdentityClaim[];
  limitation: 'parameters_unbound' | 'parameters_partially_bound' | 'all_behavior_parameters_bound';
  failureCode?: string;
}>;

export type McpIdentityResult = Readonly<{
  assurance: McpIdentityApprovalView['assurance'];
  identityMaterial: unknown;
  evidence?: ReceiptIdentityEvidence;
  approvalView: McpIdentityApprovalView;
}>;

type FieldManifest = Readonly<Record<string, unknown>>;

export type McpIdentityField = Readonly<{
  optional: boolean;
  manifest: FieldManifest;
  parse(value: unknown): SafeIdentityValue;
}>;

export type McpIdentityProfile = Readonly<{
  id: string;
  version: number;
  serverId: string;
  toolName: string;
  parameterCoverage: 'declared_subset' | 'complete_action_parameters';
  omittedCategories: readonly string[];
  expectedInputSchemaDigest?: string;
  fields: Readonly<Record<string, McpIdentityField>>;
  manifestDigest: string;
}>;

export type PreparedMcpIdentity = Readonly<{
  result: McpIdentityResult;
  dispatchParams: CallToolRequestParams;
}>;

export class ExactMcpIdentityRequiredError extends Error {
  override readonly name = 'ExactMcpIdentityRequiredError';
}

export class McpIdentityProfilePreflightError extends Error {
  override readonly name = 'McpIdentityProfilePreflightError';

  constructor(readonly code: string) {
    super(`MCP identity profile preflight failed: ${code}`);
  }
}

const trustedFields = new WeakSet<object>();
const trustedProfiles = new WeakSet<object>();
const trustedResults = new WeakSet<object>();

export function publicString(options: Readonly<{
  minLength?: number;
  maxLength?: number;
}> = {}): McpIdentityField {
  const minLength = options.minLength ?? 0;
  const maxLength = options.maxLength ?? MAX_STRING_LENGTH;
  if (!Number.isSafeInteger(minLength) || minLength < 0) throw new Error('String minimum length is invalid');
  if (!Number.isSafeInteger(maxLength) || maxLength < minLength || maxLength > MAX_STRING_LENGTH) {
    throw new Error('String maximum length is invalid');
  }
  return field({ kind: 'string', minLength, maxLength }, (value) => {
    if (typeof value !== 'string' || value.length < minLength || value.length > maxLength) {
      throw new Error('identity_field_invalid');
    }
    return Object.freeze({ type: 'string', value });
  });
}

export function publicEnum(values: readonly string[]): McpIdentityField {
  if (values.length === 0 || values.length > 100) throw new Error('Enum values are invalid');
  const unique = [...new Set(values)];
  if (unique.length !== values.length || unique.some((value) => !IDENTIFIER.test(value))) {
    throw new Error('Enum values must be unique safe identifiers');
  }
  const allowed = new Set(unique);
  return field({ kind: 'enum', values: unique }, (value) => {
    if (typeof value !== 'string' || !allowed.has(value)) throw new Error('identity_field_invalid');
    return Object.freeze({ type: 'enum', value });
  });
}

export function publicInteger(options: Readonly<{
  minimum?: number;
  maximum?: number;
}> = {}): McpIdentityField {
  const minimum = options.minimum ?? Number.MIN_SAFE_INTEGER;
  const maximum = options.maximum ?? Number.MAX_SAFE_INTEGER;
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum > maximum) {
    throw new Error('Integer range is invalid');
  }
  return field({ kind: 'integer', minimum, maximum }, (value) => {
    if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
      throw new Error('identity_field_invalid');
    }
    return Object.freeze({ type: 'integer', value: value as number });
  });
}

export function publicBoolean(): McpIdentityField {
  return field({ kind: 'boolean' }, (value) => {
    if (typeof value !== 'boolean') throw new Error('identity_field_invalid');
    return Object.freeze({ type: 'boolean', value });
  });
}

export function publicNull(): McpIdentityField {
  return field({ kind: 'null' }, (value) => {
    if (value !== null) throw new Error('identity_field_invalid');
    return Object.freeze({ type: 'null' });
  });
}

export function publicStringList(options: Readonly<{
  maxItems?: number;
  itemMaxLength?: number;
}> = {}): McpIdentityField {
  const maxItems = options.maxItems ?? MAX_LIST_ITEMS;
  const itemMaxLength = options.itemMaxLength ?? MAX_STRING_LENGTH;
  if (!Number.isSafeInteger(maxItems) || maxItems < 0 || maxItems > MAX_LIST_ITEMS) {
    throw new Error('List item limit is invalid');
  }
  if (!Number.isSafeInteger(itemMaxLength) || itemMaxLength < 0 || itemMaxLength > MAX_STRING_LENGTH) {
    throw new Error('List string limit is invalid');
  }
  return field({ kind: 'ordered_string_list', maxItems, itemMaxLength }, (value) => {
    if (!Array.isArray(value) || value.length > maxItems) throw new Error('identity_field_invalid');
    const items = value.map((item) => {
      if (typeof item !== 'string' || item.length > itemMaxLength) throw new Error('identity_field_invalid');
      return Object.freeze({ type: 'string' as const, value: item });
    });
    return Object.freeze({ type: 'ordered_list', items: Object.freeze(items) });
  });
}

export function optionalIdentityField(source: McpIdentityField): McpIdentityField {
  assertTrustedField(source);
  return field({ ...source.manifest, optional: true }, source.parse, true);
}

export function defineMcpIdentityProfile(input: Readonly<{
  id: string;
  version: number;
  serverId: string;
  toolName: string;
  parameterCoverage: 'declared_subset' | 'complete_action_parameters';
  omittedCategories?: readonly string[];
  expectedInputSchemaDigest?: string;
  fields: Readonly<Record<string, McpIdentityField>>;
}>): McpIdentityProfile {
  for (const identifier of [input.id, input.serverId, input.toolName]) assertIdentifier(identifier);
  if (!Number.isSafeInteger(input.version) || input.version < 1 || input.version > 1_000_000) {
    throw new Error('Identity profile version is invalid');
  }
  const entries = Object.entries(input.fields).sort(([left], [right]) => compareText(left, right));
  if (entries.length > MAX_FIELDS) throw new Error('Identity profile field count is invalid');
  if (entries.length === 0 && input.parameterCoverage !== 'complete_action_parameters') {
    throw new Error('Only complete identity profiles may have zero fields');
  }
  for (const [name, definition] of entries) {
    assertIdentifier(name);
    if (FORBIDDEN_FIELD.test(name)) throw new Error('Identity profile cannot disclose a credential-like field');
    assertTrustedField(definition);
  }
  const omittedCategories = [...(input.omittedCategories ?? [])].sort(compareText);
  if (omittedCategories.some((category) => !IDENTIFIER.test(category))) {
    throw new Error('Omitted categories must be safe identifiers');
  }
  if (input.parameterCoverage === 'complete_action_parameters' && omittedCategories.length !== 0) {
    throw new Error('Complete identity profiles cannot declare omitted categories');
  }
  if (input.parameterCoverage === 'declared_subset' && omittedCategories.length === 0) {
    throw new Error('Partial identity profiles must declare an omitted category');
  }
  if (input.expectedInputSchemaDigest !== undefined && !DIGEST.test(input.expectedInputSchemaDigest)) {
    throw new Error('Expected input schema digest is invalid');
  }

  const fields = Object.freeze(Object.fromEntries(entries));
  const manifest = {
    format: 'apg-mcp-identity-profile-v1',
    id: input.id,
    version: input.version,
    serverId: input.serverId,
    toolName: input.toolName,
    parameterCoverage: input.parameterCoverage,
    omittedCategories,
    ...(input.expectedInputSchemaDigest === undefined
      ? {}
      : { expectedInputSchemaDigest: input.expectedInputSchemaDigest }),
    fields: entries.map(([name, definition]) => ({
      name,
      optional: definition.optional,
      ...definition.manifest,
    })),
  };
  const profile = Object.freeze({
    id: input.id,
    version: input.version,
    serverId: input.serverId,
    toolName: input.toolName,
    parameterCoverage: input.parameterCoverage,
    omittedCategories: Object.freeze(omittedCategories),
    ...(input.expectedInputSchemaDigest === undefined
      ? {}
      : { expectedInputSchemaDigest: input.expectedInputSchemaDigest }),
    fields,
    manifestDigest: digest(manifest),
  });
  trustedProfiles.add(profile);
  return profile;
}

export class McpIdentityAuthority {
  private readonly profiles: ReadonlyMap<string, McpIdentityProfile>;
  private readonly exactRequiredKeys: ReadonlySet<string>;

  constructor(
    profiles: readonly McpIdentityProfile[] = [],
    options: Readonly<{ exactRequiredProfileIds?: readonly string[] }> = {},
  ) {
    if (profiles.length > MAX_PROFILES) throw new Error('Too many MCP identity profiles');
    const registry = new Map<string, McpIdentityProfile>();
    const profilesById = new Map<string, McpIdentityProfile>();
    for (const profile of profiles) {
      if (!trustedProfiles.has(profile)) throw new Error('Untrusted MCP identity profile');
      const key = profileKey(profile.serverId, profile.toolName);
      if (registry.has(key)) throw new Error('Duplicate MCP identity profile assignment');
      if (profilesById.has(profile.id)) throw new Error('Duplicate MCP identity profile ID');
      registry.set(key, profile);
      profilesById.set(profile.id, profile);
    }
    this.profiles = registry;

    const requiredIds = options.exactRequiredProfileIds ?? [];
    if (requiredIds.length > MAX_PROFILES || new Set(requiredIds).size !== requiredIds.length) {
      throw new Error('Exact-required MCP identity profile IDs are invalid');
    }
    const requiredKeys = new Set<string>();
    for (const id of requiredIds) {
      const profile = profilesById.get(id);
      if (profile === undefined || profile.parameterCoverage !== 'complete_action_parameters') {
        throw new Error('Exact-required MCP identity profile is unavailable or incomplete');
      }
      requiredKeys.add(profileKey(profile.serverId, profile.toolName));
    }
    this.exactRequiredKeys = requiredKeys;
  }

  prepare(
    serverId: string,
    params: CallToolRequestParams,
    inputSchema?: Tool['inputSchema'],
    requirement: 'any' | 'exact' = 'any',
  ): PreparedMcpIdentity {
    const dispatchParams = deepFreeze(structuredClone(params));
    const profile = this.profiles.get(profileKey(serverId, dispatchParams.name));
    const result = profile === undefined
      ? structuralResult(serverId, dispatchParams.name)
      : projectProfile(profile, serverId, dispatchParams, inputSchema);
    if (requirement === 'exact' && result.assurance !== 'adapter_action_exact') {
      throw new ExactMcpIdentityRequiredError('Exact MCP action identity is required but unavailable');
    }
    return Object.freeze({ result, dispatchParams });
  }

  isExactRequired(serverId: string, toolName: string): boolean {
    return this.exactRequiredKeys.has(profileKey(serverId, toolName));
  }

  preflight(serverId: string, tools: readonly Tool[]): void {
    for (const [key, profile] of this.profiles) {
      if (profile.serverId !== serverId || !this.exactRequiredKeys.has(key)) continue;
      const matches = tools.filter((tool) => tool.name === profile.toolName);
      if (matches.length === 0) throw new McpIdentityProfilePreflightError('required_tool_missing');
      if (matches.length !== 1) throw new McpIdentityProfilePreflightError('required_tool_duplicated');
      const tool = matches[0];
      if (tool === undefined) throw new McpIdentityProfilePreflightError('required_tool_missing');
      const result = this.prepare(
        serverId,
        { name: profile.toolName, arguments: {} },
        tool.inputSchema,
      ).result;
      if (result.assurance !== 'adapter_action_exact') {
        throw new McpIdentityProfilePreflightError(
          result.approvalView.failureCode ?? 'exact_identity_unavailable',
        );
      }
    }
  }
}

export function isTrustedMcpIdentityResult(value: unknown): value is McpIdentityResult {
  return typeof value === 'object' && value !== null && trustedResults.has(value);
}

export function observedInputSchemaDigest(inputSchema: Tool['inputSchema']): string {
  assertBoundedInputSchema(inputSchema);
  const canonicalSchema = canonicalReceiptJson(inputSchema);
  if (Buffer.byteLength(canonicalSchema, 'utf8') > MAX_INPUT_SCHEMA_BYTES) {
    throw new Error('MCP input schema exceeds the identity resource limit');
  }
  return digest({ format: 'apg-observed-mcp-input-schema-v1', inputSchema });
}

function assertBoundedInputSchema(inputSchema: Tool['inputSchema']): void {
  const state = { bytes: 0, nodes: 0 };
  const ancestors = new WeakSet<object>();
  const visit = (value: unknown, depth: number) => {
    state.nodes += 1;
    if (state.nodes > MAX_INPUT_SCHEMA_NODES || depth > MAX_INPUT_SCHEMA_DEPTH) {
      throw new Error('MCP input schema exceeds the identity resource limit');
    }
    if (typeof value === 'string') {
      state.bytes += Buffer.byteLength(value, 'utf8');
    } else if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
      state.bytes += 16;
    } else if (Array.isArray(value)) {
      if (ancestors.has(value)) throw new Error('MCP input schema must not be cyclic');
      ancestors.add(value);
      try {
        for (const item of value) visit(item, depth + 1);
      } finally {
        ancestors.delete(value);
      }
    } else if (typeof value === 'object' && value !== null) {
      if (ancestors.has(value)) throw new Error('MCP input schema must not be cyclic');
      ancestors.add(value);
      try {
        for (const [key, nested] of Object.entries(value)) {
          state.bytes += Buffer.byteLength(key, 'utf8');
          visit(nested, depth + 1);
        }
      } finally {
        ancestors.delete(value);
      }
    } else {
      throw new Error('MCP input schema contains an unsupported value');
    }
    if (state.bytes > MAX_INPUT_SCHEMA_BYTES) {
      throw new Error('MCP input schema exceeds the identity resource limit');
    }
  };
  visit(inputSchema, 0);
}

function projectProfile(
  profile: McpIdentityProfile,
  serverId: string,
  params: CallToolRequestParams,
  inputSchema: Tool['inputSchema'] | undefined,
): McpIdentityResult {
  let schemaDigest: string | undefined;
  try {
    if (profile.expectedInputSchemaDigest !== undefined) {
      if (inputSchema === undefined) return rejectedResult(profile, serverId, params.name, 'input_schema_unavailable');
      schemaDigest = observedInputSchemaDigest(inputSchema);
      if (schemaDigest !== profile.expectedInputSchemaDigest) {
        return rejectedResult(profile, serverId, params.name, 'input_schema_mismatch', schemaDigest);
      }
    }
    if (profile.parameterCoverage === 'complete_action_parameters' && (params._meta !== undefined || params.task !== undefined)) {
      return rejectedResult(profile, serverId, params.name, 'request_metadata_unsupported', schemaDigest);
    }
    const argumentsValue = params.arguments ?? {};
    if (!isPlainObject(argumentsValue)) return rejectedResult(profile, serverId, params.name, 'arguments_invalid', schemaDigest);
    const argumentKeys = Object.keys(argumentsValue).sort(compareText);
    const profileKeys = Object.keys(profile.fields).sort(compareText);
    if (
      profile.parameterCoverage === 'complete_action_parameters'
      && argumentKeys.some((key) => !Object.hasOwn(profile.fields, key))
    ) {
      return rejectedResult(profile, serverId, params.name, 'unexpected_argument', schemaDigest);
    }

    const claims: SafeIdentityClaim[] = [];
    for (const key of profileKeys) {
      const definition = profile.fields[key];
      if (definition === undefined) return rejectedResult(profile, serverId, params.name, 'profile_invalid', schemaDigest);
      if (!Object.hasOwn(argumentsValue, key)) {
        if (definition.optional) continue;
        return rejectedResult(profile, serverId, params.name, 'required_argument_missing', schemaDigest);
      }
      const value = definition.parse(argumentsValue[key]);
      claims.push(Object.freeze({ name: key, value }));
    }
    const frozenClaims = Object.freeze(claims);
    const evidence = evidenceFor(profile, frozenClaims, schemaDigest);
    const assurance = profile.parameterCoverage === 'complete_action_parameters'
      ? 'adapter_action_exact' as const
      : 'adapter_scoped' as const;
    return trustedResult({
      assurance,
      identityMaterial: Object.freeze({
        serverId,
        toolName: params.name,
        profileId: profile.id,
        profileVersion: profile.version,
        profileManifestDigest: profile.manifestDigest,
        safeClaims: frozenClaims,
      }),
      evidence,
      approvalView: Object.freeze({
        assurance,
        parameterCoverage: profile.parameterCoverage,
        profileId: profile.id,
        profileVersion: profile.version,
        profileStatus: 'projected',
        safeClaims: frozenClaims,
        limitation: profile.parameterCoverage === 'complete_action_parameters'
          ? 'all_behavior_parameters_bound'
          : 'parameters_partially_bound',
      }),
    });
  } catch {
    return rejectedResult(profile, serverId, params.name, 'projection_failed', schemaDigest);
  }
}

function evidenceFor(
  profile: McpIdentityProfile,
  safeClaims: readonly SafeIdentityClaim[],
  observedSchemaDigest: string | undefined,
): ReceiptIdentityEvidence {
  return Object.freeze({
    profileStatus: 'projected',
    profileId: profile.id,
    profileVersion: profile.version,
    profileManifestDigest: profile.manifestDigest,
    serverProvenanceAssurance: 'configured_label_only',
    parameterCoverage: profile.parameterCoverage,
    safeClaims,
    omittedCategories: profile.omittedCategories,
    ...(observedSchemaDigest === undefined ? {} : { observedSchemaDigest }),
  });
}

function rejectedResult(
  profile: McpIdentityProfile,
  serverId: string,
  toolName: string,
  failureCode: string,
  observedSchemaDigest?: string,
): McpIdentityResult {
  const evidence: ReceiptIdentityEvidence = Object.freeze({
    profileStatus: 'rejected',
    profileId: profile.id,
    profileVersion: profile.version,
    profileManifestDigest: profile.manifestDigest,
    serverProvenanceAssurance: 'configured_label_only',
    parameterCoverage: 'none',
    safeClaims: Object.freeze([]),
    omittedCategories: Object.freeze(['unbound_parameters']),
    failureCode,
    ...(observedSchemaDigest === undefined ? {} : { observedSchemaDigest }),
  });
  return trustedResult({
    assurance: 'structural_only',
    identityMaterial: Object.freeze({
      serverId,
      toolName,
      profileId: profile.id,
      profileVersion: profile.version,
      profileStatus: 'rejected',
      failureCode,
    }),
    evidence,
    approvalView: Object.freeze({
      assurance: 'structural_only',
      parameterCoverage: 'none',
      profileId: profile.id,
      profileVersion: profile.version,
      profileStatus: 'rejected',
      safeClaims: Object.freeze([]),
      limitation: 'parameters_unbound',
      failureCode,
    }),
  });
}

function structuralResult(serverId: string, toolName: string): McpIdentityResult {
  return trustedResult({
    assurance: 'structural_only',
    identityMaterial: Object.freeze({ serverId, toolName }),
    approvalView: Object.freeze({
      assurance: 'structural_only',
      parameterCoverage: 'none',
      safeClaims: Object.freeze([]),
      limitation: 'parameters_unbound',
    }),
  });
}

function trustedResult(result: McpIdentityResult): McpIdentityResult {
  const frozen = Object.freeze(result);
  trustedResults.add(frozen);
  return frozen;
}

function field(
  manifest: FieldManifest,
  parse: (value: unknown) => SafeIdentityValue,
  optional = false,
): McpIdentityField {
  const frozenManifest = deepFreeze(structuredClone(manifest));
  const definition = Object.freeze({ optional, manifest: frozenManifest, parse });
  trustedFields.add(definition);
  return definition;
}

function assertTrustedField(value: McpIdentityField): void {
  if (!trustedFields.has(value)) throw new Error('Untrusted identity field definition');
}

function assertIdentifier(value: string): void {
  if (!IDENTIFIER.test(value)) throw new Error('Identity profile identifier is invalid');
}

function profileKey(serverId: string, toolName: string): string {
  return `${serverId.length}:${serverId}${toolName.length}:${toolName}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalReceiptJson(value)).digest('hex')}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(value: T, ancestors: WeakSet<object> = new WeakSet<object>()): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  if (ancestors.has(value)) throw new Error('MCP request parameters must not be cyclic');
  ancestors.add(value);
  try {
    for (const nested of Object.values(value)) deepFreeze(nested, ancestors);
    return Object.freeze(value);
  } finally {
    ancestors.delete(value);
  }
}
