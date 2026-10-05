import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig, Plugin} from 'vite';

// LINT.IfChange(aistudio_media_plugin)
function aistudioMediaPlugin(): Plugin {
  return {
    name: 'vite-plugin-aistudio-media',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url && req.url.startsWith('/assets/aistudio/')) {
          const rawPath = req.url.split('?')[0].split('#')[0];
          try {
            const decodedPath = decodeURIComponent(rawPath);
            const relativePath = decodedPath.replace(/^\//, '');
            const aistudioDir = path.resolve(
              __dirname,
              'public',
              'assets',
              'aistudio',
            );
            const filePath = path.resolve(__dirname, 'public', relativePath);
            if (
              filePath.startsWith(aistudioDir + path.sep) &&
              fs.existsSync(filePath) &&
              fs.statSync(filePath).isFile()
            ) {
              const ext = path.extname(filePath).toLowerCase();
              const mimeMap: Record<string, string> = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.webp': 'image/webp',
                '.svg': 'image/svg+xml',
                '.bmp': 'image/bmp',
                '.ico': 'image/x-icon',
                '.mp4': 'video/mp4',
                '.webm': 'video/webm',
                '.ogv': 'video/ogg',
                '.mp3': 'audio/mpeg',
                '.wav': 'audio/wav',
                '.ogg': 'audio/ogg',
                '.pdf': 'application/pdf',
              };
              res.setHeader(
                'Content-Type',
                mimeMap[ext] || 'application/octet-stream',
              );
              res.setHeader('Cache-Control', 'no-cache');
              fs.createReadStream(filePath).pipe(res);
              return;
            }
          } catch {
            // Fall through if URI decoding or file access fails
          }
        }
        next();
      });
    },
  };
}
// LINT.ThenChange(//depot/google3/java/com/google/alkali/boq/makersuite/applet_dev_service/templates/initializers/react_theme/vite.config.ts:aistudio_media_plugin)

function bhumiDrishtiApiPlugin(): Plugin {
  return {
    name: 'vite-plugin-bhumidrishti-api',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || !req.url.startsWith('/api/')) {
          return next();
        }

        try {
          const url = new URL(req.url, 'http://localhost:3000');
          const pathname = url.pathname;

          // Dynamically import router to ensure TS evaluation
          const router = await server.ssrLoadModule('/src/server/apiRouter.ts');

          res.setHeader('Content-Type', 'application/json');

          if (pathname === '/api/dashboard/summary') {
            const data = router.getDashboardSummary();
            res.statusCode = 200;
            res.end(JSON.stringify(data));
            return;
          }

          if (pathname === '/api/projects') {
            const search = url.searchParams.get('search') || undefined;
            const risk = url.searchParams.get('risk') || undefined;
            const state = url.searchParams.get('state') || undefined;
            const stage = url.searchParams.get('stage') || undefined;
            const data = router.getProjects({ search, risk, state, stage });
            res.statusCode = 200;
            res.end(JSON.stringify(data));
            return;
          }

          if (pathname.startsWith('/api/projects/')) {
            const id = pathname.replace('/api/projects/', '');
            const proj = router.getProjectById(id);
            if (proj) {
              res.statusCode = 200;
              res.end(JSON.stringify(proj));
            } else {
              res.statusCode = 404;
              res.end(JSON.stringify({ error: 'Project not found' }));
            }
            return;
          }

          if (pathname === '/api/alerts') {
            const alerts = router.getAlerts();
            res.statusCode = 200;
            res.end(JSON.stringify(alerts));
            return;
          }

          if (pathname.startsWith('/api/alerts/') && pathname.endsWith('/acknowledge')) {
            const parts = pathname.split('/');
            const id = parts[3];
            const alert = router.acknowledgeAlert(id);
            res.statusCode = 200;
            res.end(JSON.stringify(alert || {}));
            return;
          }

          if (pathname === '/api/risk-map') {
            const data = router.getRiskMapData();
            res.statusCode = 200;
            res.end(JSON.stringify(data));
            return;
          }

          if (pathname === '/api/system/status') {
            const data = router.getSystemStatus ? router.getSystemStatus() : { status: 'active' };
            res.statusCode = 200;
            res.end(JSON.stringify(data));
            return;
          }

          if (pathname === '/api/ml/metrics' || pathname === '/api/ml/model-info') {
            const data = router.getModelInfo ? router.getModelInfo() : {};
            res.statusCode = 200;
            res.end(JSON.stringify(data));
            return;
          }

          if (pathname === '/api/what-if' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => {
              body += chunk;
            });
            req.on('end', () => {
              try {
                const parsed = JSON.parse(body || '{}');
                const result = router.runWhatIfScenario(parsed);
                res.statusCode = 200;
                res.end(JSON.stringify(result));
              } catch (e: any) {
                res.statusCode = 400;
                res.end(JSON.stringify({ error: e.message }));
              }
            });
            return;
          }

          if (pathname.startsWith('/api/datahub/')) {
            if (pathname === '/api/datahub/projects') {
              const data = router.DataHubApi.getProjects();
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname.startsWith('/api/datahub/projects/') && pathname.endsWith('/history')) {
              const pId = pathname.replace('/api/datahub/projects/', '').replace('/history', '');
              const data = router.DataHubApi.getProjectHistory(pId);
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname.startsWith('/api/datahub/projects/')) {
              const pId = pathname.replace('/api/datahub/projects/', '');
              const data = router.DataHubApi.getProjectById(pId);
              if (data) {
                res.statusCode = 200;
                res.end(JSON.stringify(data));
              } else {
                res.statusCode = 404;
                res.end(JSON.stringify({ error: 'Project not found in Data Hub' }));
              }
              return;
            }
            if (pathname === '/api/datahub/changes') {
              const limit = url.searchParams.get('limit') ? parseInt(url.searchParams.get('limit')!, 10) : 30;
              const data = router.DataHubApi.getRecentChanges(limit);
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname === '/api/datahub/sync-status' || pathname === '/api/datahub/overview') {
              const data = router.DataHubApi.getSyncStatus();
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname === '/api/datahub/sync-runs') {
              const data = router.DataHubApi.getSyncRuns(15);
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname === '/api/datahub/source-status') {
              const data = router.DataHubApi.getSourceStatus();
              res.statusCode = 200;
              res.end(JSON.stringify(data));
              return;
            }
            if (pathname === '/api/datahub/sync' && req.method === 'POST') {
              const run = await router.DataHubApi.triggerSync();
              res.statusCode = 200;
              res.end(JSON.stringify({ message: 'Sync completed', run }));
              return;
            }
            if (pathname === '/api/datahub/source/test' && req.method === 'POST') {
              let body = '';
              req.on('data', chunk => { body += chunk; });
              req.on('end', async () => {
                const parsed = JSON.parse(body || '{}');
                const result = await router.DataHubApi.testSource(parsed.projectId);
                res.statusCode = 200;
                res.end(JSON.stringify(result));
              });
              return;
            }
          }

          next();
        } catch (err: any) {
          console.error('[Vite Plugin API Error]', err);
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: err.message, stack: err.stack }));
        }
      });
    }
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), aistudioMediaPlugin(), bhumiDrishtiApiPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâfile watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
