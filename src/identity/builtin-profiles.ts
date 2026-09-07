import {
  defineMcpIdentityProfile,
  McpIdentityAuthority,
  observedInputSchemaDigest,
} from './mcp-identity.js';

export const FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID =
  'filesystem.list-allowed-directories.v1';

export const FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL = 'list_allowed_directories';

// Captured from the public tools/list response of the pinned 2026.7.10 runtime
// during its separately approved isolated acceptance. Future drift fails closed.
const LIST_ALLOWED_DIRECTORIES_INPUT_SCHEMA = Object.freeze({
  type: 'object' as const,
  properties: Object.freeze({}),
  $schema: 'http://json-schema.org/draft-07/schema#',
});

export const FILESYSTEM_LIST_ALLOWED_DIRECTORIES_SCHEMA_DIGEST =
  observedInputSchemaDigest(LIST_ALLOWED_DIRECTORIES_INPUT_SCHEMA);

const filesystemListAllowedDirectoriesProfile = defineMcpIdentityProfile({
  id: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
  version: 1,
  serverId: 'local-upstream',
  toolName: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL,
  parameterCoverage: 'complete_action_parameters',
  expectedInputSchemaDigest: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_SCHEMA_DIGEST,
  fields: {},
});

export type BuiltInMcpIdentitySelection = Readonly<{
  profileId: typeof FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID;
  toolName: typeof FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL;
  authority: McpIdentityAuthority;
}>;

export function selectBuiltInMcpIdentityProfile(profileId: string): BuiltInMcpIdentitySelection {
  if (profileId !== FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID) {
    throw new Error('Unknown or invalid MCP identity profile');
  }

  return Object.freeze({
    profileId: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
    toolName: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL,
    authority: new McpIdentityAuthority(
      [filesystemListAllowedDirectoriesProfile],
      { exactRequiredProfileIds: [FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID] },
    ),
  });
}
