export type StdioUpstreamConfig = Readonly<{
  serverId: string;
  command: string;
  args: readonly string[];
  cwd?: string;
  env: Readonly<Record<string, string>>;
}>;
