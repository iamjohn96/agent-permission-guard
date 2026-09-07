import { Server, type CallToolResult } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';

let listAllowedDirectoriesCallCount = 0;

serveStdio(() => {
  const server = new Server(
    { name: 'apg-exact-filesystem-fixture', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler('tools/list', async () => ({
    tools: [
      {
        name: 'list_allowed_directories',
        description: 'Returns a synthetic private path for exact identity tests.',
        inputSchema: {
          type: 'object',
          properties: {},
          $schema: 'http://json-schema.org/draft-07/schema#',
        },
        annotations: { readOnlyHint: true, openWorldHint: false },
      },
      {
        name: 'get_list_allowed_directories_call_count',
        description: 'Returns the synthetic list_allowed_directories call count.',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'echo',
        description: 'Echoes a message.',
        inputSchema: {
          type: 'object',
          properties: { message: { type: 'string' } },
          required: ['message'],
        },
      },
    ],
  }));

  server.setRequestHandler('tools/call', async (request): Promise<CallToolResult> => {
    if (request.params.name === 'list_allowed_directories') {
      listAllowedDirectoriesCallCount += 1;
      return { content: [{ type: 'text', text: '/private/synthetic/allowed-root' }] };
    }
    if (request.params.name === 'get_list_allowed_directories_call_count') {
      return { content: [{ type: 'text', text: String(listAllowedDirectoriesCallCount) }] };
    }
    if (request.params.name === 'echo') {
      const message = request.params.arguments?.message;
      if (typeof message !== 'string') {
        return { content: [{ type: 'text', text: 'invalid echo arguments' }], isError: true };
      }
      return { content: [{ type: 'text', text: message }] };
    }
    return { content: [{ type: 'text', text: 'unknown fixture tool' }], isError: true };
  });

  return server;
});
