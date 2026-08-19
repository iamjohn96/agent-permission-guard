import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

let dangerousCallCount = 0;
let startedWaitCount = 0;
let cancelledWaitCount = 0;

serveStdio(() => {
  const server = new McpServer(
    { name: 'apg-mock-server', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    'echo',
    {
      description: 'Echoes a message.',
      inputSchema: z.object({ message: z.string() }),
    },
    async ({ message }) => ({ content: [{ type: 'text', text: message }] }),
  );

  server.registerTool(
    'dangerous_write',
    {
      description: 'Fixture tool that records an attempted write.',
      inputSchema: z.object({ value: z.string() }),
    },
    async ({ value }) => {
      dangerousCallCount += 1;
      return { content: [{ type: 'text', text: `wrote:${value}` }] };
    },
  );

  server.registerTool(
    'get_dangerous_call_count',
    {
      description: 'Returns the number of dangerous_write calls.',
      inputSchema: z.object({}),
    },
    async () => ({
      content: [{ type: 'text', text: String(dangerousCallCount) }],
    }),
  );

  server.registerTool(
    'wait_for_cancel',
    {
      description: 'Waits long enough for cancellation propagation tests.',
      inputSchema: z.object({ delayMs: z.number().int().positive() }),
    },
    async ({ delayMs }, context) => new Promise((resolve, reject) => {
      startedWaitCount += 1;
      const timeout = setTimeout(() => {
        resolve({ content: [{ type: 'text', text: 'completed' }] });
      }, delayMs);

      context.mcpReq.signal.addEventListener('abort', () => {
        cancelledWaitCount += 1;
        clearTimeout(timeout);
        reject(new Error('fixture wait cancelled'));
      }, { once: true });
    }),
  );

  server.registerTool(
    'get_started_wait_count',
    {
      description: 'Returns the number of started wait calls.',
      inputSchema: z.object({}),
    },
    async () => ({
      content: [{ type: 'text', text: String(startedWaitCount) }],
    }),
  );

  server.registerTool(
    'get_cancelled_wait_count',
    {
      description: 'Returns the number of cancelled wait calls.',
      inputSchema: z.object({}),
    },
    async () => ({
      content: [{ type: 'text', text: String(cancelledWaitCount) }],
    }),
  );

  return server;
});
