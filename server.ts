import 'dotenv/config';
import express from 'express';
import path from 'path';
import fs from 'node:fs';
import { createServer as createViteServer } from 'vite';
import * as api from './src/server/apiRouter.ts';
import {
  authenticateToken,
  requireAuth,
  requireRole,
  verifyToken,
  createDemoToken,
  recordSession,
  revokeSession,
  getUserAccountByEmail,
  authenticateWithPassword,
  isDemoModeEnabled,
  validateAuthEnvironment,
  AuthUser
} from './src/server/auth.ts';
import { AuditService } from './src/server/auditService.ts';
import { CsvManagementService } from './src/server/csvManagement.ts';
import { getDatabase } from './src/server/database.ts';
import { createRateLimiter } from './src/server/rateLimiter.ts';
import {
  executeShadowScoring,
  queryShadowPredictions,
  inspectCandidateArtifact,
  SHADOW_POLICY_CONFIG
} from './src/server/ml/shadowRunner.ts';
import { ShadowMonitoringService } from './src/server/ml/shadowMonitoringService.ts';
import { ShadowMonitoringStore } from './src/server/ml/shadowMonitoringStore.ts';
import { ShadowEvaluationService } from './src/server/ml/shadowEvaluationService.ts';
import { ShadowEvaluationStore } from './src/server/ml/shadowEvaluationStore.ts';
import { StatutoryStore } from './src/server/datahub/statutoryStore.ts';

export async function createExpressApp(): Promise<express.Express> {
  // Validate production authentication environment and reject dangerous defaults
  const authValidation = validateAuthEnvironment();
  if (!authValidation.ok) {
    console.error('[FATAL AUTH CONFIGURATION ERROR]:', authValidation.error);
    if (process.env.NODE_ENV === 'production' && !isDemoModeEnabled()) {
      throw new Error(authValidation.error);
    }
  }

  const app = express();
  const PORT = 3000;

  // Serverless Environment Compatibility: Ensure socket and IP properties exist safely
  app.use((req, _res, next) => {
    if (!req.socket) {
      (req as any).socket = { remoteAddress: '127.0.0.1' };
    } else if (!req.socket.remoteAddress) {
      const xff = req.headers ? (req.headers['x-forwarded-for'] as string) : undefined;
      const addr = xff ? xff.split(',')[0].trim() : '127.0.0.1';
      try {
        Object.defineProperty(req.socket, 'remoteAddress', { value: addr, configurable: true, writable: true });
      } catch {
        (req.socket as any).remoteAddress = addr;
      }
    }
    next();
  });

  // Rate Limiting Middlewares (DoS Prevention & Resource Protection)
  const apiRateLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 500,
    message: 'Rate limit exceeded for general API endpoints. Please wait before retrying.'
  });

  const sensitiveRateLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 60,
    message: 'Rate limit exceeded for sensitive operations. Please wait before retrying.'
  });

  // Middleware for JSON and URL encoded payloads (supports CSV/JSON imports up to 10MB)
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // CORS & Institutional Security Headers
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-auth-token, x-user-role, x-test-rate-limit');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), payment=(), usb=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');

    // Strict Content-Security-Policy compliant with AI Studio iframe preview & Leaflet maps
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://*.firebaseio.com; " +
      "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; " +
      "img-src 'self' data: blob: https:; " +
      "connect-src 'self' https: wss:; " +
      "font-src 'self' data: https://fonts.gstatic.com; " +
      "frame-ancestors 'self' https:; " +
      "base-uri 'self'; " +
      "form-action 'self';"
    );

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }
    next();
  });

  // Global API Rate Limiter
  app.use('/api', apiRateLimiter);

  // Global Session and Token Authentication Middleware
  app.use(authenticateToken);

  // ==========================================
  // AUTHENTICATION & RBAC ENDPOINTS (PHASE 0.6)
  // ==========================================
  app.get('/api/auth/me', (req, res) => {
    const demoActive = isDemoModeEnabled();
    res.status(200).json({
      isAuthenticated: !!req.user,
      user: req.user || null,
      availableRoles: ['VIEWER', 'NODAL_OFFICER', 'AUDITOR'],
      demoMode: demoActive,
      demoCredentials: demoActive ? {
        nodalEmail: 'nodal.officer@morth.gov.in',
        auditorEmail: 'viewer.auditor@gov.in',
        password: process.env.AUTH_DEV_PASSWORD || 'BhoomiDev#Test2026'
      } : undefined
    });
  });

  app.post('/api/auth/login', sensitiveRateLimiter, async (req, res) => {
    const dbInstance = getDatabase();
    try {
      const { idToken, email, password } = req.body || {};

      // 1. Genuine Firebase ID Token Login
      if (idToken && typeof idToken === 'string') {
        const result = await verifyToken(dbInstance, idToken);
        if (!result.valid || !result.user) {
          AuditService.record(dbInstance, {
            userId: 'UNKNOWN',
            userName: 'Failed Login Attempt',
            userRole: 'UNAUTHENTICATED',
            action: 'LOGIN_FAILURE',
            resource: 'auth_system',
            result: 'DENIED',
            ipAddress: req.ip,
            details: { reason: result.reason || 'Invalid Firebase ID token', error: result.error }
          });

          res.status(result.status || 401).json({
            success: false,
            error: result.error || 'INVALID_FIREBASE_TOKEN',
            message: result.reason || 'Firebase authentication failed.'
          });
          return;
        }

        const user = result.user;
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        recordSession(dbInstance, idToken, user, expiresAt);

        AuditService.record(dbInstance, {
          userId: user.id,
          userName: user.name,
          userRole: user.role,
          action: 'LOGIN_SUCCESS',
          resource: 'auth_system',
          result: 'SUCCESS',
          ipAddress: req.ip,
          details: { authProvider: 'firebase', email: user.email }
        });

        res.status(200).json({
          success: true,
          token: idToken,
          expiresAt,
          user
        });
        return;
      }

      // 2. Authoritative Email & Password Login (Institutional Credentials)
      if (email && password && typeof email === 'string' && typeof password === 'string') {
        const authResult = await authenticateWithPassword(dbInstance, email, password);
        if (!authResult.valid || !authResult.user || !authResult.token) {
          AuditService.record(dbInstance, {
            userId: 'UNKNOWN',
            userName: 'Failed Credential Login',
            userRole: 'UNAUTHENTICATED',
            action: 'LOGIN_FAILURE',
            resource: 'auth_system',
            result: 'DENIED',
            ipAddress: req.ip,
            details: { email, error: authResult.error, reason: authResult.reason }
          });

          res.status(authResult.status || 401).json({
            success: false,
            error: authResult.error || 'INVALID_CREDENTIALS',
            message: authResult.reason || 'Invalid email or password.'
          });
          return;
        }

        const user = authResult.user;
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        AuditService.record(dbInstance, {
          userId: user.id,
          userName: user.name,
          userRole: user.role,
          action: 'LOGIN_SUCCESS',
          resource: 'auth_system',
          result: 'SUCCESS',
          ipAddress: req.ip,
          details: { authProvider: 'institutional_credentials', email: user.email }
        });

        res.status(200).json({
          success: true,
          token: authResult.token,
          expiresAt,
          user
        });
        return;
      }

      // Neither Firebase ID token nor email/password provided
      AuditService.record(dbInstance, {
        userId: 'UNKNOWN',
        userName: 'Malformed Login Request',
        userRole: 'UNAUTHENTICATED',
        action: 'LOGIN_FAILURE',
        resource: 'auth_system',
        result: 'DENIED',
        ipAddress: req.ip,
        details: { reason: 'Missing credentials in request payload' }
      });

      res.status(400).json({
        success: false,
        error: 'CREDENTIALS_REQUIRED',
        message: 'Email and password (or Firebase ID token) are required to authenticate.'
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Login failed' });
    }
  });

  app.post('/api/auth/logout', (req, res) => {
    try {
      const dbInstance = getDatabase();
      if (req.token) {
        revokeSession(dbInstance, req.token);
      }
      if (req.user) {
        AuditService.record(dbInstance, {
          userId: req.user.id,
          userName: req.user.name,
          userRole: req.user.role,
          action: 'LOGOUT',
          resource: 'auth_system',
          result: 'SUCCESS',
          ipAddress: req.ip
        });
      }
      res.status(200).json({ success: true, message: 'Logged out successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Logout failed' });
    }
  });

  app.post('/api/auth/switch-role', async (req, res) => {
    const dbInstance = getDatabase();
    try {
      // STRICT DEMO MODE ISOLATION (Requirement 9):
      // The persona switcher must NEVER grant production privileges or run outside demo mode.
      if (!isDemoModeEnabled()) {
        AuditService.record(dbInstance, {
          userId: req.user?.id || 'ANONYMOUS',
          userName: req.user?.name || 'Anonymous User',
          userRole: req.user?.role || 'UNAUTHENTICATED',
          action: 'ACCESS_DENIED',
          resource: 'auth_system',
          result: 'DENIED',
          ipAddress: req.ip,
          details: { reason: 'Persona switching is permanently disabled in production mode.' }
        });

        res.status(403).json({
          error: 'DEMO_MODE_DISABLED',
          message: 'Direct persona switching is permanently disabled in production mode. Official Firebase Authentication is required.'
        });
        return;
      }

      const { role } = req.body || {};
      if (role !== 'VIEWER' && role !== 'NODAL_OFFICER') {
        res.status(400).json({ error: "Invalid role. Must be 'VIEWER' or 'NODAL_OFFICER'." });
        return;
      }

      const targetEmail = role === 'VIEWER' ? 'viewer.auditor@gov.in' : 'nodal.officer@morth.gov.in';
      const targetUser = getUserAccountByEmail(dbInstance, targetEmail);

      if (!targetUser) {
        res.status(404).json({ error: 'Statutory persona account not found in database.' });
        return;
      }

      const token = await createDemoToken({ uid: targetUser.id, email: targetUser.email }, 86400);
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      recordSession(dbInstance, token, targetUser, expiresAt);

      AuditService.record(dbInstance, {
        userId: targetUser.id,
        userName: targetUser.name,
        userRole: targetUser.role,
        action: 'ROLE_SWITCH',
        resource: 'user_session',
        result: 'SUCCESS',
        ipAddress: req.ip,
        details: { switchedTo: role, isDemo: true }
      });

      res.status(200).json({
        success: true,
        token,
        expiresAt,
        user: targetUser,
        isDemo: true
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to switch role' });
    }
  });

  // Health and Info Endpoints
  app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'BhoomiDrishti Intelligence' });
  });

  app.get('/api/info', (_req, res) => {
    res.status(200).json({
      system: 'BhoomiDrishti Land Acquisition Risk Intelligence Platform',
      version: '2.5.0',
      description: 'Predictive Analytics System for Early Detection of Land Acquisition Delays (SIH26017) - Government of India',
      capabilities: ['BhoomiRashi Adapter', 'LACRRIS Adapter', 'Official File Ingestion', 'Dynamic ML Risk Scoring', 'Server-Side Pagination']
    });
  });

  // Dashboard Summary
  app.get('/api/dashboard/summary', requireAuth, (_req, res) => {
    try {
      const summary = api.getDashboardSummary();
      res.status(200).json(summary);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch dashboard summary' });
    }
  });

  // Paginated and Filtered Projects
  app.get('/api/projects', requireAuth, (req, res) => {
    try {
      const search = req.query.search ? String(req.query.search) : undefined;
      const risk = req.query.risk ? String(req.query.risk) : undefined;
      const state = req.query.state ? String(req.query.state) : undefined;
      const district = req.query.district ? String(req.query.district) : undefined;
      const stage = req.query.stage ? String(req.query.stage) : undefined;
      const sortBy = req.query.sortBy ? String(req.query.sortBy) : undefined;
      const page = req.query.page ? parseInt(String(req.query.page), 10) : 1;
      const pageSize = req.query.pageSize ? parseInt(String(req.query.pageSize), 10) : 100;

      const result = api.getProjects({ search, risk, state, district, stage, sortBy, page, pageSize });
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to query projects' });
    }
  });

  // Project Creation Endpoint (with validation, ML scoring, and audit trail)
  app.post('/api/projects', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const user = req.user!;
      const result = api.createProject(req.body, user.id);
      if (!result.success) {
        res.status(400).json({ error: result.error || 'Failed to create project' });
        return;
      }

      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'PROJECT_CREATE',
        resource: 'projects',
        resourceId: result.project?.id || req.body?.id,
        result: 'SUCCESS',
        newValue: req.body
      });

      res.status(201).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Error creating project' });
    }
  });

  // Single Project Details
  app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
      const project = api.getProjectById(req.params.id);
      if (!project) {
        res.status(404).json({ error: 'Project not found' });
        return;
      }

      // Delegate to authoritative ML Prediction Bridge for strict baseline parity (Rule 18)
      try {
        const mlResult = await api.mlBridge.predictForProject(project.id);
        if (mlResult && mlResult.success && mlResult.prediction) {
          project.delayProbability = Math.round(mlResult.prediction.delay_probability * 1000) / 10;
          project.riskLevel = mlResult.prediction.risk_level;
          (project as any).mlPrediction = {
            delay_probability: mlResult.prediction.delay_probability,
            raw_probability: mlResult.prediction.raw_probability,
            risk_level: mlResult.prediction.risk_level,
            model_version: mlResult.model?.model_version || 'BHOOMI-DRISHTI-ML-V1.0',
            status: mlResult.model?.status || 'EXPERIMENTAL',
            algorithm: mlResult.model?.algorithm || 'Class-Weighted Random Forest',
            feature_provenance: mlResult.metadata?.feature_provenance || 'database'
          };
        }
      } catch (mlErr) {
        console.warn(`[ML Prediction] Could not calculate real-time ML score for ${project.id}:`, mlErr);
      }

      res.status(200).json(project);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch project' });
    }
  });

  // Project Change History (Audit Trail)
  app.get('/api/projects/:id/history', requireAuth, (req, res) => {
    try {
      const history = api.getProjectHistory(req.params.id);
      res.status(200).json(history);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch project history' });
    }
  });

  // Project Deletion Endpoint (Strictly requires NODAL_OFFICER)
  app.delete('/api/projects/:id', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const user = req.user!;
      const oldProject = api.getProjectById(req.params.id);
      if (!oldProject) {
        res.status(404).json({ error: 'Project not found' });
        return;
      }
      const result = api.deleteProject(req.params.id, user.id);
      if (!result.success) {
        res.status(400).json({ error: result.error || 'Failed to delete project' });
        return;
      }

      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'PROJECT_DELETE',
        resource: 'projects',
        resourceId: req.params.id,
        result: 'SUCCESS',
        oldValue: oldProject
      });

      res.status(200).json({ success: true, message: 'Project deleted successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Error deleting project' });
    }
  });

  // Alerts
  app.get('/api/alerts', requireAuth, (req, res) => {
    try {
      const status = req.query.status ? String(req.query.status) : undefined;
      const alerts = api.getAlerts(status);
      res.status(200).json(alerts);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch alerts' });
    }
  });

  app.post('/api/alerts/:id/acknowledge', requireRole(['NODAL_OFFICER', 'VIEWER']), (req, res) => {
    try {
      const user = req.user!;
      const updated = api.acknowledgeAlert(req.params.id);
      if (!updated) {
        res.status(404).json({ error: 'Alert not found' });
        return;
      }
      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'CONFIGURATION_CHANGE',
        resource: 'alerts',
        resourceId: req.params.id,
        result: 'SUCCESS',
        ipAddress: req.ip,
        details: { alertId: req.params.id, action: 'ACKNOWLEDGE' }
      });
      res.status(200).json({ success: true, alert: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to acknowledge alert' });
    }
  });

  // Risk Map lightweight data
  app.get('/api/risk-map', requireAuth, (_req, res) => {
    try {
      const mapData = api.getRiskMapData();
      res.status(200).json(mapData);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch map data' });
    }
  });

  // What-If Scenario Calculation (Phase 3.5 ML Model Sensitivity Engine)
  app.post('/api/scenarios/what-if', requireAuth, sensitiveRateLimiter, async (req, res) => {
    const dbInstance = getDatabase();
    try {
      const result = await api.mlBridge.runWhatIfScenario(req.body);
      if (!result.success) {
        let statusCode = 400;
        if (result.error_code === 'PROJECT_NOT_FOUND') {
          statusCode = 404;
        } else if (
          result.error_code === 'MODEL_INTEGRITY_ERROR' ||
          result.error_code === 'MODEL_NOT_FOUND' ||
          result.error_code === 'MODEL_PREDICTION_ERROR'
        ) {
          statusCode = 500;
        }
        res.status(statusCode).json(result);
        return;
      }

      // Safe Audit Logging (Without PII, secrets, or training contamination)
      try {
        const user = (req as any).user;
        AuditService.record(dbInstance, {
          userId: user?.id || 'ANONYMOUS',
          userName: user?.name || 'API Client',
          userRole: user?.role || 'VIEWER',
          action: 'PREDICTION_GENERATION',
          resource: 'what_if_engine',
          result: 'SUCCESS',
          ipAddress: req.ip,
          details: {
            projectId: result.projectId,
            changedFeaturesCount: result.changed_features ? Object.keys(result.changed_features).length : 0,
            percentagePointChange: result.change?.percentage_point_change,
            modelVersion: result.model?.version
          }
        });
      } catch (auditErr) {
        console.warn('[AuditService] Non-fatal scenario audit logging error:', auditErr);
      }

      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error_code: 'SCENARIO_SIMULATION_ERROR',
        error: err.message || 'What-if calculation failed'
      });
    }
  });

  // System and Source Status
  app.get('/api/system/status', requireAuth, (_req, res) => {
    try {
      const status = api.getSystemStatus();
      res.status(200).json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch system status' });
    }
  });

  app.get('/api/system/source-status', requireAuth, async (_req, res) => {
    try {
      const sources = await api.getSourcesStatus();
      res.status(200).json(sources);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch source status' });
    }
  });

  app.get('/api/sources/status', requireAuth, async (_req, res) => {
    try {
      const sources = await api.getSourcesStatus();
      res.status(200).json(sources);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch source status' });
    }
  });

  // Data Sources Management
  app.get('/api/data-sources', requireAuth, (_req, res) => {
    try {
      const sources = api.getDataSources();
      res.status(200).json(sources);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch data sources' });
    }
  });

  app.get('/api/data-sources/:id', requireAuth, (req, res) => {
    try {
      const source = api.getDataSourceById(req.params.id);
      if (!source) {
        res.status(404).json({ error: 'Data source not found' });
        return;
      }
      res.status(200).json(source);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch data source' });
    }
  });

  app.put('/api/data-sources/:id', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const updated = api.updateDataSourceConfig(req.params.id, req.body);
      if (!updated) {
        res.status(404).json({ error: 'Data source not found' });
        return;
      }
      res.status(200).json({ success: true, dataSource: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update data source' });
    }
  });

  app.post('/api/data-sources/:id/test', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const result = await api.testDataSourceConnection(req.params.id);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to test connection' });
    }
  });

  // Project Update Endpoint (with validation, ML recalculation, and immutable audit trail)
  app.put('/api/projects/:id', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const user = req.user!;
      const oldProject = api.getProjectById(req.params.id);
      const result = api.updateProject(req.params.id, req.body, user.id);
      if (!result.success) {
        res.status(400).json({ error: result.error || 'Failed to update project' });
        return;
      }

      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'PROJECT_UPDATE',
        resource: 'projects',
        resourceId: req.params.id,
        result: 'SUCCESS',
        oldValue: oldProject,
        newValue: req.body
      });

      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Error updating project' });
    }
  });

  // Explicit Verification Workflow (Part D: Nodal Officer verification with authoritative reference)
  app.post('/api/projects/:id/verify', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const user = req.user!;
      const { authoritative_source_ref } = req.body || {};
      if (!authoritative_source_ref || typeof authoritative_source_ref !== 'string' || !authoritative_source_ref.trim()) {
        res.status(400).json({ error: 'Authoritative source reference is required to verify a project.' });
        return;
      }
      const result = api.verifyProject(req.params.id, authoritative_source_ref.trim(), user.name || user.email);
      if (!result.success) {
        res.status(400).json({ error: result.error || 'Failed to verify project' });
        return;
      }
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Error verifying project' });
    }
  });

  // Operational Data Quality Summary (Part H)
  app.get('/api/datahub/quality-summary', requireAuth, (_req, res) => {
    try {
      const summary = api.getDataQualitySummary();
      res.status(200).json(summary);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Error retrieving data quality summary' });
    }
  });

  // ==========================================
  // PRODUCTION CSV MANAGEMENT PIPELINE
  // Stage 1 & 2: UPLOAD & VALIDATE (Strictly requires NODAL_OFFICER role)
  // ==========================================
  app.post('/api/csv/upload', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const { csvContent, fileName } = req.body || {};
      if (!csvContent || typeof csvContent !== 'string') {
        res.status(400).json({ error: 'Missing or invalid csvContent in request payload.' });
        return;
      }
      const user = req.user!;
      const dbInstance = getDatabase();
      const session = CsvManagementService.stageAndValidateCsv(dbInstance, csvContent, fileName || 'upload.csv', user);
      res.status(200).json({ success: true, session });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to process CSV upload' });
    }
  });

  // Stage 3: PREVIEW STAGED CSV SESSION
  app.get('/api/csv/preview/:sessionId', (req, res) => {
    try {
      const session = CsvManagementService.getSessionPreview(req.params.sessionId);
      res.status(200).json(session);
    } catch (err: any) {
      res.status(404).json({ error: err.message || 'CSV staging session not found' });
    }
  });

  // Stage 4: APPROVE STAGED CSV (Strictly requires NODAL_OFFICER role)
  app.post('/api/csv/approve/:sessionId', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const { reviewNote } = req.body || {};
      const user = req.user!;
      const session = CsvManagementService.approveSession(req.params.sessionId, user, reviewNote);
      res.status(200).json({ success: true, session });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to approve staged session' });
    }
  });

  // Stage 5 & 6: COMMIT ATOMIC IMPORT & AUDIT (Strictly requires NODAL_OFFICER role)
  app.post('/api/csv/commit/:sessionId', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const user = req.user!;
      const dbInstance = getDatabase();
      const result = CsvManagementService.commitImport(dbInstance, req.params.sessionId, user);
      res.status(200).json({ success: true, result });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Atomic CSV commit failed' });
    }
  });

  // CSV EXPORT (Sanitized against CSV Injection)
  app.get('/api/csv/export', requireRole(['NODAL_OFFICER', 'VIEWER', 'AUDITOR']), (req, res) => {
    try {
      const user = req.user!;
      const dbInstance = getDatabase();
      const csvData = CsvManagementService.exportProjectsToCsv(dbInstance, user);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="bhoomidrishti_projects_export.csv"');
      res.status(200).send(csvData);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Export failed' });
    }
  });

  // ==========================================
  // IMMUTABLE AUDIT LOG QUERY ENDPOINT
  // Strictly requires NODAL_OFFICER role
  // ==========================================
  app.get('/api/audit-logs', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const action = req.query.action ? String(req.query.action) : undefined;
      const userId = req.query.userId ? String(req.query.userId) : undefined;
      const resource = req.query.resource ? String(req.query.resource) : undefined;
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;
      const offset = req.query.offset ? parseInt(String(req.query.offset), 10) : 0;

      const dbInstance = getDatabase();
      const result = AuditService.query(dbInstance, { action, userId, resource, limit, offset });
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to query audit logs' });
    }
  });

  // File Inspection Endpoint (pre-upload column mapping preview)
  app.post('/api/data/inspect', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const { content, fileType, fileName } = req.body || {};
      if (!content || !fileType) {
        res.status(400).json({ error: 'Missing file content or fileType (must be csv, xlsx, xls, or json)' });
        return;
      }
      const inspection = api.inspectFile(content, fileType, fileName);
      res.status(200).json(inspection);
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to inspect file structure' });
    }
  });

  // File Ingestion with Column Mapping Endpoint (Strictly requires NODAL_OFFICER)
  app.post('/api/data/import-mapped', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { content, fileType, columnMapping, fileName } = req.body || {};
      if (!content || !fileType) {
        res.status(400).json({ error: 'Missing content or fileType' });
        return;
      }
      const summary = await api.importDataWithMapping(content, fileType, columnMapping, fileName || 'upload');
      res.status(200).json({
        message: 'Data import completed',
        summary
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Mapped file import failed' });
    }
  });

  // Validation Errors Log
  app.get('/api/validation-errors', (req, res) => {
    try {
      const syncId = req.query.syncId ? String(req.query.syncId) : undefined;
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;
      const errors = api.getValidationErrors(syncId, limit);
      res.status(200).json(errors);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch validation errors' });
    }
  });

  // Database Overview
  app.get('/api/database/overview', (_req, res) => {
    try {
      const overview = api.getDatabaseOverview();
      res.status(200).json(overview);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch database overview' });
    }
  });

  // Data Export (CSV or JSON)
  app.get('/api/export', (req, res) => {
    try {
      const type = (req.query.type || 'all') as 'all' | 'high_risk' | 'alerts' | 'audit_logs';
      const format = (req.query.format || 'json') as 'csv' | 'json';
      const data = api.exportData(type, format);

      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="bhoomidrishti_${type}_export.csv"`);
        res.status(200).send(data);
      } else {
        res.status(200).json(data);
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to export data' });
    }
  });

  // Data Mode Toggle (DEMO vs LIVE_SYNCHRONIZED - Strictly requires NODAL_OFFICER)
  app.post('/api/system/data-mode', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const mode = req.body?.mode;
      if (!mode || (mode !== 'DEMO' && mode !== 'LIVE_SYNCHRONIZED')) {
        res.status(400).json({ error: "Invalid mode. Must be 'DEMO' or 'LIVE_SYNCHRONIZED'" });
        return;
      }
      const result = api.setDataMode(mode);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update data mode' });
    }
  });

  // Data Synchronization Endpoint (Strictly requires NODAL_OFFICER)
  app.post('/api/sync', sensitiveRateLimiter, requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const source = (req.body?.source || 'BhoomiRashi') as any;
      const summary = await api.triggerSync(source);
      res.status(200).json({
        message: `Synchronization with ${source} completed`,
        summary
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Synchronization failed' });
    }
  });

  // Official File Ingestion Endpoint (CSV / XLSX / JSON - Strictly requires NODAL_OFFICER)
  app.post('/api/data/import', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { content, fileType, fileName } = req.body || {};
      if (!content || !fileType) {
        res.status(400).json({ error: 'Missing content or fileType (must be csv, xlsx, or json)' });
        return;
      }
      const summary = await api.importData(content, fileType, fileName || 'upload');
      res.status(200).json({
        message: 'Official data import completed',
        summary
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'File import failed' });
    }
  });

  // Sync History
  app.get('/api/sync/history', (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 10;
      const history = api.getSyncHistory(limit);
      res.status(200).json(history);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch sync history' });
    }
  });

  // Baseline Model Info (SIH Reference Rules)
  app.get('/api/model/info', (_req, res) => {
    res.status(200).json(api.getModelInfo());
  });

  // ============================================================
  // PHASE 0: ML DATASET FOUNDATION & READINESS AUDIT REST API
  // ============================================================

  // 1. GET /api/ml/readiness-audit (Comprehensive 16-point audit report)
  app.get('/api/ml/readiness-audit', (_req, res) => {
    try {
      const audit = api.getMLReadinessAudit();
      res.status(200).json(audit);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to generate ML readiness audit' });
    }
  });

  // 2. GET /api/ml/dataset/summary
  app.get('/api/ml/dataset/summary', (_req, res) => {
    try {
      const audit = api.getMLReadinessAudit();
      res.status(200).json({
        totalProjects: audit.totalProjects,
        provenanceBreakdown: audit.provenanceBreakdown,
        totalSnapshots: audit.totalSnapshots,
        totalLabelledObservations: audit.totalLabelledObservations,
        classDistribution: audit.classDistribution,
        unresolvedCount: audit.unresolvedObservationsCount,
        eligibleTrainingCount: audit.minimumSampleSizeEvaluation.currentEligibleObservations,
        finalDetermination: audit.finalDetermination,
        deficitToMinimumTarget: audit.additionalObservationsRequired.deficit
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch dataset summary' });
    }
  });

  // 3. GET /api/ml/dataset/observations
  app.get('/api/ml/dataset/observations', (req, res) => {
    try {
      const eligibleOnly = req.query.eligibleOnly === 'true';
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 100;
      const observations = api.getHistoricalObservations({ eligibleOnly, limit });
      res.status(200).json(observations);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch labelled observations' });
    }
  });

  // 4. GET /api/ml/dataset/snapshots
  app.get('/api/ml/dataset/snapshots', (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 100;
      const snapshots = api.getHistoricalSnapshots(limit);
      res.status(200).json(snapshots);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch historical snapshots' });
    }
  });

  // 5. GET /api/ml/future-pipeline-spec
  app.get('/api/ml/future-pipeline-spec', (_req, res) => {
    res.status(200).json(api.getFuturePipelineSpec());
  });

  // 6. POST /api/ml/dataset/bootstrap (Strictly requires NODAL_OFFICER)
  app.post('/api/ml/dataset/bootstrap', requireRole(['NODAL_OFFICER']), async (_req, res) => {
    try {
      const db = (await import('./src/server/database.ts')).getDatabase();
      const result = await api.HistoricalDataIngestionEngine.bootstrapHistoricalDataset(db);
      res.status(200).json({ message: 'Historical dataset bootstrapped', result });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to bootstrap historical dataset' });
    }
  });

  // ============================================================
  // PHASE 3: SUPERVISED ML PREDICTION & INFERENCE REST API
  // Model Artifact: BHOOMI-DRISHTI-ML-V1.0 (Status: EXPERIMENTAL)
  // ============================================================

  // 1. POST /api/ml/predict (Supervised Delay Risk Prediction)
  app.post('/api/ml/predict', sensitiveRateLimiter, async (req, res) => {
    const dbInstance = getDatabase();
    try {
      const payload = req.body || {};
      const { projectId } = payload;

      let predictionResult;
      if (projectId && typeof projectId === 'string') {
        // Project ID mode: Extract 9 features deterministically from authoritative DB/snapshots
        predictionResult = await api.mlBridge.predictForProject(projectId);
      } else {
        // Direct features mode: Predict based on 9 approved features provided in payload
        const inputFeatures = payload.features && typeof payload.features === 'object' ? payload.features : payload;
        predictionResult = await api.mlBridge.predict(inputFeatures);
      }

      if (!predictionResult.success) {
        let statusCode = 400;
        if (predictionResult.error_code === 'PROJECT_NOT_FOUND') {
          statusCode = 404;
        } else if (
          predictionResult.error_code === 'MODEL_INTEGRITY_ERROR' ||
          predictionResult.error_code === 'MODEL_NOT_FOUND' ||
          predictionResult.error_code === 'MODEL_PREDICTION_ERROR'
        ) {
          statusCode = 500;
        }

        res.status(statusCode).json(predictionResult);
        return;
      }

      // Safe Audit Logging (Without PII, secrets, or training contamination)
      try {
        const user = (req as any).user;
        AuditService.record(dbInstance, {
          userId: user?.id || 'ANONYMOUS',
          userName: user?.name || 'API Client',
          userRole: user?.role || 'VIEWER',
          action: 'PREDICTION_GENERATION',
          resource: 'ml_model_v1.0',
          result: 'SUCCESS',
          ipAddress: req.ip,
          details: {
            projectId: predictionResult.metadata?.projectId || null,
            delayProbability: predictionResult.prediction?.delay_probability,
            riskLevel: predictionResult.prediction?.risk_level,
            modelVersion: predictionResult.model?.model_version,
            status: predictionResult.model?.status
          }
        });
      } catch (auditErr) {
        console.warn('[AuditService] Non-fatal prediction audit logging error:', auditErr);
      }

      res.status(200).json(predictionResult);
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error_code: 'MODEL_PREDICTION_ERROR',
        error: err.message || 'Internal error executing ML prediction'
      });
    }
  });

  // 2. GET /api/ml/model-info (Canonical Supervised ML Model Metadata)
  app.get('/api/ml/model-info', (_req, res) => {
    try {
      const info = api.mlBridge.getModelInfo();
      res.status(200).json(info);
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error_code: 'MODEL_INFO_ERROR',
        error: err.message || 'Failed to retrieve model info'
      });
    }
  });

  // ============================================================
  // PHASE 1: DATA HUB / DATA SYNCHRONIZATION REST API ENDPOINTS
  // ============================================================

  // Initialize Data Hub periodic scheduler
  api.DataHubScheduler.init();

  // 1. GET /api/datahub/projects (Current synchronized projects)
  app.get('/api/datahub/projects', (_req, res) => {
    try {
      const projects = api.DataHubApi.getProjects();
      res.status(200).json(projects);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch Data Hub projects' });
    }
  });

  // 2. GET /api/datahub/projects/:sourceProjectId (Full project detail)
  app.get('/api/datahub/projects/:sourceProjectId', (req, res) => {
    try {
      const project = api.DataHubApi.getProjectById(req.params.sourceProjectId);
      if (!project) {
        res.status(404).json({ error: `Project '${req.params.sourceProjectId}' not found in Data Hub` });
        return;
      }
      res.status(200).json(project);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch Data Hub project' });
    }
  });

  // 3. GET /api/datahub/projects/:sourceProjectId/history (Historical snapshots & field diffs)
  app.get('/api/datahub/projects/:sourceProjectId/history', (req, res) => {
    try {
      const history = api.DataHubApi.getProjectHistory(req.params.sourceProjectId);
      res.status(200).json(history);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch project history' });
    }
  });

  // 4. GET /api/datahub/changes (Recent field-level changes across projects)
  app.get('/api/datahub/changes', (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 30;
      const changes = api.DataHubApi.getRecentChanges(limit);
      res.status(200).json(changes);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch recent changes' });
    }
  });

  // 5. GET /api/datahub/sync-status and /api/datahub/overview
  app.get(['/api/datahub/sync-status', '/api/datahub/overview'], (_req, res) => {
    try {
      const status = api.DataHubApi.getSyncStatus();
      res.status(200).json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch sync status' });
    }
  });

  // 6. GET /api/datahub/sync-runs (Audit log of synchronization runs)
  app.get('/api/datahub/sync-runs', (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 15;
      const runs = api.DataHubApi.getSyncRuns(limit);
      res.status(200).json(runs);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch sync runs' });
    }
  });

  // 7. POST /api/datahub/sync (Trigger manual "Check Now")
  app.post('/api/datahub/sync', sensitiveRateLimiter, requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const user = req.user!;
      const run = await api.DataHubApi.triggerSync();
      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'DATAHUB_MANUAL_SYNC',
        resource: 'datahub',
        result: 'SUCCESS',
        ipAddress: req.ip,
        details: { syncRunId: run.id, status: run.status }
      });
      res.status(200).json({
        message: 'Synchronization run completed',
        run
      });
    } catch (err: any) {
      console.error('[DataHub Sync Error]', err);
      res.status(500).json({ error: err.message || 'Synchronization run failed' });
    }
  });

  // 8. POST /api/datahub/projects/register (Register a new public project ID)
  app.post('/api/datahub/projects/register', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { projectId, projectName, discoveryMethod } = req.body || {};
      if (!projectId) {
        res.status(400).json({ error: 'Project ID is required' });
        return;
      }
      const result = await api.DataHubApi.registerProject(projectId, projectName, discoveryMethod);
      res.status(result.isNew ? 201 : 200).json(result);
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to register project' });
    }
  });

  // 9. POST /api/datahub/projects/import (Bulk import project IDs)
  app.post('/api/datahub/projects/import', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { content, format } = req.body || {};
      if (!content) {
        res.status(400).json({ error: 'Missing content for project ID import' });
        return;
      }
      const result = await api.DataHubApi.importProjectIds(content, format || 'csv');
      res.status(200).json(result);
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to import project IDs' });
    }
  });

  // 10. GET /api/datahub/source-status (Source configuration & status)
  app.get('/api/datahub/source-status', (_req, res) => {
    try {
      const status = api.DataHubApi.getSourceStatus();
      res.status(200).json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch source status' });
    }
  });

  // 11. POST /api/datahub/source/test (Test public source connectivity)
  app.post('/api/datahub/source/test', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { projectId } = req.body || {};
      const result = await api.DataHubApi.testSource(projectId);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Source test failed' });
    }
  });

  // 12. POST /api/datahub/test-fixture/toggle-60940 (Isolated test fixture for regression test harness)
  app.post('/api/datahub/test-fixture/toggle-60940', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      if (process.env.NODE_ENV === 'production' && process.env.DEMO_MODE !== 'true') {
        res.status(403).json({
          success: false,
          error: 'TEST_FIXTURE_DISABLED',
          message: 'Development and evaluation test fixtures are strictly disabled in production mode.'
        });
        return;
      }
      const enabled = req.body?.enabled;
      const result = api.DataHubApi.toggleFixture60940(enabled);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to toggle test fixture' });
    }
  });

  // 13. PUT /api/datahub/config (Update periodic interval)
  app.put('/api/datahub/config', requireRole(['NODAL_OFFICER']), (req, res) => {
    try {
      const interval = parseInt(String(req.body?.intervalMinutes), 10);
      if (isNaN(interval) || interval <= 0) {
        res.status(400).json({ error: 'Valid intervalMinutes is required' });
        return;
      }
      const result = api.DataHubApi.updateConfig(interval);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update config' });
    }
  });

  // 14. GET /api/datahub/export (Export Data Hub records)
  app.get('/api/datahub/export', (req, res) => {
    try {
      const format = (req.query.format as any) === 'json' ? 'json' : 'csv';
      const data = api.DataHubApi.exportData(format);
      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="bhoomirashi_datahub_export.csv"');
        res.status(200).send(data);
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.status(200).send(data);
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to export Data Hub data' });
    }
  });

  // 15. GET /api/datahub/discovery/status (Technical limitation & architecture report)
  app.get(['/api/datahub/discovery/status', '/api/datahub/discovery/limitation-report'], (_req, res) => {
    try {
      const report = api.DataHubApi.getDiscoveryLimitationReport();
      res.status(200).json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch discovery report' });
    }
  });

  // 16. POST /api/datahub/discovery/candidates (Controlled Candidate Queue Ingestion - Strictly NODAL_OFFICER)
  app.post('/api/datahub/discovery/candidates', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { candidateIds } = req.body || {};
      if (!Array.isArray(candidateIds) || candidateIds.length === 0) {
        res.status(400).json({ error: 'candidateIds array is required' });
        return;
      }
      const user = (req as any).user;
      const report = await api.DataHubApi.discoverCandidates(candidateIds, user);
      res.status(200).json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Candidate discovery run failed' });
    }
  });

  // 17. POST /api/datahub/discovery/probe-range (Controlled Statutory Range Discovery - Strictly NODAL_OFFICER)
  app.post('/api/datahub/discovery/probe-range', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const { baseProjectId, windowSize } = req.body || {};
      if (!baseProjectId) {
        res.status(400).json({ error: 'baseProjectId is required' });
        return;
      }
      const user = (req as any).user;
      const report = await api.DataHubApi.discoverRange(String(baseProjectId), windowSize || 1, user);
      res.status(200).json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Range discovery probe failed' });
    }
  });

  // --- PHASE 7B-4: AUTHORITATIVE STATUTORY EVIDENCE & INGESTION APIS ---

  // GET /api/datahub/sources (Registered statutory sources & health status)
  app.get('/api/datahub/sources', async (_req, res) => {
    try {
      const { BhoomiRashiStatutoryAdapter, LacrrisStatutoryAdapter } = await import('./src/server/datahub/statutoryAdapters.ts');
      const br = new BhoomiRashiStatutoryAdapter();
      const lac = new LacrrisStatutoryAdapter();
      const [brHealth, lacHealth] = await Promise.all([br.healthCheck(), lac.healthCheck()]);
      res.status(200).json({
        sources: [
          {
            name: br.sourceName,
            type: br.sourceType,
            health: brHealth,
            authoritative: true
          },
          {
            name: lac.sourceName,
            type: lac.sourceType,
            health: lacHealth,
            authoritative: false
          },
          {
            name: 'Manual Official Ingestion',
            type: 'MANUAL_OFFICIAL_DOCUMENT',
            health: { accessible: true, message: 'Ready for official gazette uploads', timestamp: new Date().toISOString() },
            authoritative: true
          }
        ]
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to query statutory sources' });
    }
  });

  // GET /api/datahub/projects/:id/evidence (Complete statutory evidence report)
  app.get('/api/datahub/projects/:id/evidence', async (req, res) => {
    try {
      const result = await api.DataHubApi.getProjectEvidence(req.params.id);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch project statutory evidence' });
    }
  });

  // GET /api/datahub/projects/:id/notifications (Authoritative statutory notifications)
  app.get('/api/datahub/projects/:id/notifications', async (req, res) => {
    try {
      const notifs = await api.DataHubApi.getProjectNotifications(req.params.id);
      res.status(200).json(notifs);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch statutory notifications' });
    }
  });

  // GET /api/datahub/projects/:id/evidence-quality
  app.get('/api/datahub/projects/:id/evidence-quality', async (req, res) => {
    try {
      const quality = await api.DataHubApi.getProjectEvidenceQuality(req.params.id);
      res.status(200).json(quality);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch evidence quality' });
    }
  });

  // POST /api/datahub/ingestion/validate (Strict validation before upload)
  app.post('/api/datahub/ingestion/validate', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const result = await api.DataHubApi.validateIngestionPayload(req.body || {});
      res.status(result.valid ? 200 : 400).json(result);
    } catch (err: any) {
      res.status(500).json({ valid: false, error: err.message || 'Validation failed' });
    }
  });

  // POST /api/datahub/ingestion/import (Manual official document ingestion - NODAL_OFFICER only)
  app.post('/api/datahub/ingestion/import', sensitiveRateLimiter, requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const user = req.user!;
      const {
        fileName,
        mimeType,
        base64Content,
        projectId,
        sourceReference,
        statutorySection,
        notificationNumber,
        publicationDate,
        sourceUrl
      } = req.body || {};

      if (!fileName || !base64Content || !projectId || !statutorySection || !notificationNumber || !publicationDate) {
        res.status(400).json({ error: 'Missing required statutory upload fields.' });
        return;
      }

      const buffer = Buffer.from(base64Content, 'base64');
      const result = await api.DataHubApi.importOfficialDocument({
        fileName,
        mimeType: mimeType || 'application/pdf',
        buffer,
        projectId,
        sourceReference: sourceReference || 'Official Gazette Filing',
        statutorySection,
        notificationNumber,
        publicationDate,
        uploaderId: user.id,
        uploaderName: user.name,
        sourceUrl
      });

      const dbInstance = getDatabase();
      AuditService.record(dbInstance, {
        userId: user.id,
        userName: user.name,
        userRole: user.role,
        action: 'STATUTORY_DOCUMENT_INGESTION',
        resource: 'dh_authoritative_statutory_notifications',
        resourceId: result.recordId || projectId,
        result: result.success ? 'SUCCESS' : 'FAILED',
        ipAddress: req.ip,
        details: { projectId, notificationNumber, publicationDate, status: result.status }
      });

      res.status(result.success ? 200 : 400).json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Document ingestion failed' });
    }
  });

  // GET /api/datahub/review-queue
  app.get('/api/datahub/review-queue', requireRole(['NODAL_OFFICER', 'AUDITOR']), async (req, res) => {
    try {
      const status = req.query.status as any;
      const items = await api.DataHubApi.getReviewQueue(status);
      res.status(200).json(items);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to query review queue' });
    }
  });

  // POST /api/datahub/review-queue/:id/decision (NODAL_OFFICER only)
  app.post('/api/datahub/review-queue/:id/decision', requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const user = req.user!;
      const { decision, notes } = req.body || {};
      if (!decision || !['APPROVED', 'REJECTED', 'REQUEST_MORE_EVIDENCE'].includes(decision)) {
        res.status(400).json({ error: 'Valid decision (APPROVED, REJECTED, REQUEST_MORE_EVIDENCE) is required' });
        return;
      }
      const success = await api.DataHubApi.recordReviewDecision(
        req.params.id,
        decision,
        { id: user.id, name: user.name },
        notes
      );
      res.status(200).json({ success });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to record review decision' });
    }
  });

  // POST /api/datahub/sync/:source (NODAL_OFFICER only)
  app.post('/api/datahub/sync/:source', sensitiveRateLimiter, requireRole(['NODAL_OFFICER']), async (req, res) => {
    try {
      const source = req.params.source as 'BhoomiRashi' | 'LACRRIS';
      if (!['BhoomiRashi', 'LACRRIS'].includes(source)) {
        res.status(400).json({ error: 'Unsupported statutory source' });
        return;
      }
      const run = await api.DataHubApi.triggerStatutorySync(source);
      res.status(200).json({ success: true, run });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Sync failed' });
    }
  });


  // --- SHADOW-MODE CANDIDATE EVALUATION ENDPOINTS (Phase 6A) ---
  // 18. GET /api/shadow/runs (Accessible to authenticated roles: NODAL_OFFICER, AUDITOR, VIEWER)
  app.get('/api/shadow/runs', requireRole(['NODAL_OFFICER', 'AUDITOR', 'VIEWER']), (req, res) => {
    try {
      const dbInstance = getDatabase();
      const { projectId, predictionState, limit, offset } = req.query as any;
      const result = queryShadowPredictions(dbInstance, {
        projectId,
        predictionState,
        limit: limit ? parseInt(limit, 10) : 50,
        offset: offset ? parseInt(offset, 10) : 0
      });
      res.status(200).json({ success: true, ...result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to query shadow predictions' });
    }
  });

  // 19. GET /api/shadow/diagnostics (Accessible to authenticated roles: NODAL_OFFICER, AUDITOR, VIEWER)
  app.get('/api/shadow/diagnostics', requireRole(['NODAL_OFFICER', 'AUDITOR', 'VIEWER']), (_req, res) => {
    try {
      const artifact = inspectCandidateArtifact();
      res.status(200).json({
        success: true,
        policyConfig: SHADOW_POLICY_CONFIG,
        artifact,
        status: 'SHADOW_MODE_OFFLINE_BENCHMARK',
        isOperational: false
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve shadow diagnostics' });
    }
  });

  // 19b. GET /api/shadow/project/:id (Project-level shadow diagnostics and statutory evidence quality)
  app.get('/api/shadow/project/:id', requireRole(['NODAL_OFFICER', 'AUDITOR', 'VIEWER']), (req, res) => {
    try {
      const dbInstance = getDatabase();
      const projectId = req.params.id;
      const result = queryShadowPredictions(dbInstance, { projectId, limit: 1 });
      const quality = StatutoryStore.getProjectEvidenceQuality(projectId);
      res.status(200).json({
        success: true,
        projectId,
        quality,
        shadowRecord: result.records.length > 0 ? result.records[0] : null,
        governanceState: 'PENDING_STAKEHOLDER_APPROVAL',
        disclosure: 'SHADOW / DIAGNOSTIC ONLY — NOT AN OPERATIONAL RISK SCORE',
        isOperational: false
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve project shadow diagnostics' });
    }
  });

  // 20. POST /api/shadow/score (Restricted to NODAL_OFFICER & AUDITOR)
  app.post('/api/shadow/score', sensitiveRateLimiter, requireRole(['NODAL_OFFICER', 'AUDITOR']), (req, res) => {
    try {
      const dbInstance = getDatabase();
      const user = (req as any).user;
      const result = executeShadowScoring(dbInstance, req.body, user);
      res.status(200).json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Shadow scoring execution failed' });
    }
  });

  // ========================================================================
  // PHASE 7B-6: SHADOW MONITORING, DRIFT & OUTCOME TRACKING APIS
  // ========================================================================

  // 21. GET /api/shadow/monitoring/summary
  app.get('/api/shadow/monitoring/summary', (req, res) => {
    try {
      const latest = ShadowMonitoringStore.getLatestMonitoringRun();
      if (latest) {
        const parsed = JSON.parse(latest.metrics_json);
        res.status(200).json({ success: true, summary: parsed });
      } else {
        const report = ShadowMonitoringService.executeMonitoringCycle((req as any).user);
        res.status(200).json({ success: true, summary: report });
      }
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve shadow monitoring summary' });
    }
  });

  // 22. GET /api/shadow/monitoring/evidence
  app.get('/api/shadow/monitoring/evidence', (_req, res) => {
    try {
      const coverage = ShadowMonitoringService.evaluateEvidenceCoverage();
      res.status(200).json({ success: true, evidence: coverage });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evidence coverage' });
    }
  });

  // 23. GET /api/shadow/monitoring/features
  app.get('/api/shadow/monitoring/features', (_req, res) => {
    try {
      const snapshots = ShadowMonitoringStore.getRecentFeatureSnapshots(50);
      res.status(200).json({ success: true, features: snapshots });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve feature snapshots' });
    }
  });

  // 24. GET /api/shadow/monitoring/drift
  app.get('/api/shadow/monitoring/drift', (req, res) => {
    try {
      const latest = ShadowMonitoringStore.getLatestMonitoringRun();
      if (latest) {
        const parsed = JSON.parse(latest.metrics_json);
        res.status(200).json({ success: true, drift: parsed.featureDrift, status: latest.drift_status });
      } else {
        const report = ShadowMonitoringService.executeMonitoringCycle((req as any).user);
        res.status(200).json({ success: true, drift: report.featureDrift, status: report.driftStatus });
      }
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve drift report' });
    }
  });

  // 25. GET /api/shadow/monitoring/predictions
  app.get('/api/shadow/monitoring/predictions', (req, res) => {
    try {
      const latest = ShadowMonitoringStore.getLatestMonitoringRun();
      if (latest) {
        const parsed = JSON.parse(latest.metrics_json);
        res.status(200).json({ success: true, predictions: parsed.predictionDistribution });
      } else {
        const report = ShadowMonitoringService.executeMonitoringCycle((req as any).user);
        res.status(200).json({ success: true, predictions: report.predictionDistribution });
      }
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve prediction distribution' });
    }
  });

  // 26. GET /api/shadow/monitoring/outcomes
  app.get('/api/shadow/monitoring/outcomes', (_req, res) => {
    try {
      const outcomes = ShadowMonitoringStore.getOutcomes();
      const summary = ShadowMonitoringService.reconcileOutcomes();
      res.status(200).json({ success: true, outcomes, summary });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve eventual outcomes' });
    }
  });

  // 27. GET /api/shadow/monitoring/performance
  app.get('/api/shadow/monitoring/performance', (_req, res) => {
    try {
      const summary = ShadowMonitoringService.reconcileOutcomes();
      res.status(200).json({ success: true, performance: summary });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve performance metrics' });
    }
  });

  // 28. POST /api/shadow/monitoring/run (Restricted to NODAL_OFFICER & AUDITOR)
  app.post('/api/shadow/monitoring/run', sensitiveRateLimiter, requireRole(['NODAL_OFFICER', 'AUDITOR']), (req, res) => {
    try {
      const user = (req as any).user;
      const report = ShadowMonitoringService.executeMonitoringCycle(user);
      res.status(200).json({ success: true, report });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to execute monitoring cycle' });
    }
  });

  // 29. POST /api/shadow/monitoring/outcomes/reconcile (Restricted to NODAL_OFFICER)
  app.post('/api/shadow/monitoring/outcomes/reconcile', sensitiveRateLimiter, requireRole(['NODAL_OFFICER']), (_req, res) => {
    try {
      const summary = ShadowMonitoringService.reconcileOutcomes();
      res.status(200).json({ success: true, summary });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to reconcile outcomes' });
    }
  });

  // ============================================================
  // PHASE 7B-7: SHADOW EVALUATION REST APIS
  // ============================================================

  // 30. GET /api/shadow/evaluation/summary
  app.get('/api/shadow/evaluation/summary', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({ success: true, summary });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evaluation summary' });
    }
  });

  // 31. GET /api/shadow/evaluation/runs
  app.get('/api/shadow/evaluation/runs', (_req, res) => {
    try {
      const runs = ShadowEvaluationStore.getRuns(50);
      res.status(200).json({ success: true, runs });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evaluation runs' });
    }
  });

  // 32. POST /api/shadow/evaluation/run (Restricted to NODAL_OFFICER & AUDITOR)
  app.post('/api/shadow/evaluation/run', sensitiveRateLimiter, requireRole(['NODAL_OFFICER', 'AUDITOR']), (req, res) => {
    try {
      const user = (req as any).user;
      const options = req.body || {};
      const result = ShadowEvaluationService.executeEvaluationRun(
        user?.id || 'officer_web',
        user?.name || 'Authorized Nodal Officer',
        user?.role || 'NODAL_OFFICER',
        options
      );
      res.status(200).json({ success: true, run: result.run, summary: result.summary });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to execute evaluation run' });
    }
  });

  // 33. GET /api/shadow/evaluation/outcomes
  app.get('/api/shadow/evaluation/outcomes', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        runId: summary.latestRunId,
        matureObservations: summary.matureObservations,
        delayedCount: summary.delayedCount,
        onTimeCount: summary.onTimeCount,
        reliabilityBins: summary.reliabilityBins
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evaluation outcomes' });
    }
  });

  // 34. GET /api/shadow/evaluation/performance
  app.get('/api/shadow/evaluation/performance', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        evaluationState: summary.evaluationState,
        isStatisticallySufficient: summary.isStatisticallySufficient,
        discrimination: summary.metrics,
        message: summary.message
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve performance metrics' });
    }
  });

  // 35. GET /api/shadow/evaluation/calibration
  app.get('/api/shadow/evaluation/calibration', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        calibration: {
          brierScore: summary.metrics.brierScore,
          logLoss: summary.metrics.logLoss,
          calibrationSlope: summary.metrics.calibrationSlope,
          calibrationIntercept: summary.metrics.calibrationIntercept,
          ece: summary.metrics.ece,
          status: summary.metrics.calibrationStatus,
          reliabilityBins: summary.reliabilityBins
        }
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve calibration metrics' });
    }
  });

  // 36. GET /api/shadow/evaluation/thresholds
  app.get('/api/shadow/evaluation/thresholds', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        policyStatus: summary.thresholdPolicyStatus,
        diagnosticThresholds: summary.diagnosticThresholds,
        disclaimer: 'Diagnostic threshold analysis — no operational threshold approved.'
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve diagnostic thresholds' });
    }
  });

  // 37. GET /api/shadow/evaluation/comparison
  app.get('/api/shadow/evaluation/comparison', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        comparison: summary.v1v2Comparison
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve comparison' });
    }
  });

  // 38. GET /api/shadow/evaluation/coverage
  app.get('/api/shadow/evaluation/coverage', (_req, res) => {
    try {
      const summary = ShadowEvaluationService.getEvaluationSummary();
      res.status(200).json({
        success: true,
        coverageBias: summary.coverageBias
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve coverage bias report' });
    }
  });

  // 39. GET /api/shadow/evaluation/exclusions
  app.get('/api/shadow/evaluation/exclusions', (req, res) => {
    try {
      const runId = req.query.runId as string | undefined;
      const exclusions = ShadowEvaluationStore.getExclusions(runId);
      res.status(200).json({
        success: true,
        count: exclusions.length,
        exclusions
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evaluation exclusions' });
    }
  });

  // 40. GET /api/shadow/evaluation/evidence-package (Restricted to authenticated users)
  app.get('/api/shadow/evaluation/evidence-package', requireAuth, (_req, res) => {
    try {
      const packagePath = path.resolve(process.cwd(), 'data/shadow_evaluation/phase_7b10_evidence_package.json');
      if (!fs.existsSync(packagePath)) {
        return res.status(404).json({ success: false, error: 'Evidence package not found.' });
      }
      const data = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
      res.status(200).json({
        success: true,
        evidencePackage: data
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to retrieve evidence package' });
    }
  });

  // 404 Fallback for unhandled API endpoints (prevents HTML SPA fallback on /api/*)
  app.all('/api/*', (req, res) => {
    res.status(404).json({
      success: false,
      error: 'NOT_FOUND',
      message: `API endpoint '${req.method} ${req.path}' not found.`
    });
  });

  // Global Error Handler: Suppress internal stack traces in client responses
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[BhoomiDrishti Server Unhandled Error]:', err);
    res.status(err.status || 500).json({
      success: false,
      error: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message || 'An unexpected internal error occurred.'
    });
  });

  return app;
}

export async function startServer() {
  const app = await createExpressApp();
  const PORT = Number(process.env.PORT) || 3000;

  // Vite middleware in dev or static files in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return new Promise<express.Express>((resolve) => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[BhumiDrishti Server] Running on http://0.0.0.0:${PORT} (env: ${process.env.NODE_ENV || 'development'})`);
      resolve(app);
    });
  });
}

// Auto-start server in standalone Node execution (bypassed in Vercel serverless context and test runners)
const isMainScript = typeof process !== 'undefined' && process.argv[1] && (
  process.argv[1].endsWith('server.ts') ||
  process.argv[1].endsWith('server.cjs') ||
  process.argv[1].endsWith('server.js')
);

if (isMainScript && !process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME) {
  startServer().catch((err) => {
    console.error('[BhumiDrishti Server] Failed to start:', err);
  });
}
