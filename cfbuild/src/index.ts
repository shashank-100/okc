import { getSandbox, Sandbox } from "@cloudflare/sandbox";

export { Sandbox };

interface Env {
  Sandbox: DurableObjectNamespace<Sandbox>;
  BUILD_TOKEN: string;
}

// POST /exec  {"cmd": "..."}                 -> {exitCode, stdout, stderr}
// POST /write {"path": "...", "content": "..."} -> {ok}
// Every request needs "Authorization: Bearer <BUILD_TOKEN>". One builder box, kept warm between builds.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.headers.get("authorization") !== `Bearer ${env.BUILD_TOKEN}`) {
      return new Response("unauthorized", { status: 401 });
    }
    if (request.method !== "POST") return new Response("POST only", { status: 405 });
    const box = getSandbox(env.Sandbox, "builder", { sleepAfter: "60m" });
    const path = new URL(request.url).pathname;
    const body = (await request.json()) as { cmd?: string; path?: string; content?: string };
    if (path === "/exec" && body.cmd) {
      const r = await box.exec(body.cmd);
      return Response.json({ exitCode: r.exitCode, stdout: r.stdout, stderr: r.stderr });
    }
    if (path === "/write" && body.path && body.content !== undefined) {
      await box.writeFile(body.path, body.content);
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  },
};
