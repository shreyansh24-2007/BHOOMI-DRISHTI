# 🏛️ BHOOMI-DRISHTI: PRODUCTION RELEASE & OPERATIONAL HANDOVER PACKAGE
**Ministry of Road Transport & Highways (MoRTH) / National Highways Authority of India (NHAI)**  
**Platform Version:** `1.0.0-RELEASE-READY`  
**Statutory Authority:** National Highways Act, 1956 [Sections 3A, 3D, 3G]  
**Release Date / Timestamp:** `2026-09-30T13:45:00.000Z`  
**Target Environment:** Google Cloud Run (Containerized Node.js 22 LTS runtime)

---

## 1. EXECUTIVE SUMMARY & MODEL GOVERNANCE DECLARATION

BHOOMI-DRISHTI has achieved the **RELEASE_READY** governance tier following successful execution and verification of Phase UI-1, UI-2, UI-3, and FINAL-1 test gates.

### ⚠️ MANDATORY MODEL GOVERNANCE INVARIANTS:
1. **Production Model**: `BHOOMI-DRISHTI-ML-V1.0` remains the **SOLE AUTHORITATIVE OPERATIONAL SYSTEM**.
2. **Candidate Model**: `BHOOMI-DRISHTI-ML-V2.0-SHADOW` operates strictly in isolated **SHADOW EVALUATION MODE (`SHADOW_CANDIDATE / NON_OPERATIONAL`)**.
3. **No Model Promotion**: V2 **HAS NOT BEEN PROMOTED** to production.
4. **No Operational Impact**: V2 shadow probabilities **NEVER ALTER** operational risk scores, delay probabilities, priority ranks, executive alerts, or administrative recommendations.
5. **Threshold Governance**: Decision threshold policies strictly remain **`PENDING_STAKEHOLDER_APPROVAL`**.
6. **Zero Dangerous Controls**: No user interface control, API endpoint, or background script exists that can promote V2 or activate decision thresholds.

---

## 2. CANONICAL CRYPTOGRAPHIC INVARIANTS (100% VERIFIED)

| Component | Canonical Identifier / Path | Verified SHA-256 Hash | Status |
| :--- | :--- | :--- | :--- |
| **Production Model V1** | `data/ml_models/BHOOMI-DRISHTI-ML-V1.0/model_pipeline.joblib` | `7e0e1a7dac2e082c20c7e0baa9eafa9f7aa2a120cd10c7a5b129537c0e91307f` | **MATCH** |
| **Candidate Model V2** | `data/ml_models/BHOOMI-DRISHTI-ML-V2.0-SHADOW/model_pipeline.joblib` | `4a83e980f9178498be4592a47303f0ebc5ea641934952af5bee92ae5b76729a2` | **MATCH** |
| **Baseline Dataset** | `data/reconstructed_longitudinal_dataset_v2.json` | `0da40152ca0866ec54b0a3500186f5ae450b487095bb1a09a0563b95605f052a` | **MATCH** |
| **Feature Contract** | `SCHEMA-LONGITUDINAL-V2.0-10FEAT` | 10 ordered longitudinal features (0 quarantined leakage keys) | **MATCH** |
| **Operational Cohort** | Active projects registry in SQLite (`data/bhoomidrishti.db`) | Exactly 31 operational highway corridors | **MATCH** |

---

## 3. TEST EXECUTION & VERIFICATION SUMMARY

| Test Suite Category | Script / Entry Point | Assertions Passed | Status |
| :--- | :--- | :--- | :--- |
| **UI-1: Shadow Governance UI** | `scripts/run_ui_phase1_tests.ts` | 21 / 21 | **PASS** |
| **UI-2: Integration & Security** | `scripts/run_ui_phase2_validation.ts` | 24 / 24 | **PASS** |
| **UI-3: UX Polish & Accessibility**| `scripts/run_ui_phase3_validation.ts` | 22 / 22 | **PASS** |
| **FINAL-1: Release Audit** | `scripts/run_final_release_audit.ts` | 23 / 23 | **PASS** |
| **End-to-End User Journeys** | `scripts/verify_user_journeys.ts` | 16 / 16 | **PASS** |
| **Phase 7B-11 Shadow Evidence** | `scripts/run_phase_7b11_tests.ts` | 21 / 21 | **PASS** |
| **Phase 5 Security & RBAC** | `scripts/runTests.ts` (Suites 10-12, 20) | 79 / 79 | **PASS** |
| **TypeScript Compilation** | `npx tsc --noEmit` | 0 errors | **PASS** |
| **Production Application Build** | `npm run build` (Vite + esbuild) | Bundled successfully | **PASS** |
| **Database Integrity Check** | `PRAGMA integrity_check` | Status: `ok` | **PASS** |
| **Total Verified Assertions** | Complete Repository Test Matrix | **145 Passed** (TypeScript) | **PASS** |

### ⚠️ Documented Python Runtime Limitation:
- **Environment Status**: `PYTHON_JOBLIB_VALIDATION = BLOCKED`
- **Cause**: The container's Python runtime (`/usr/bin/python3`, Python 3.10.12) does not contain `pip` or the `joblib` package (`python3 -c "import joblib"` raises `ModuleNotFoundError: No module named 'joblib'`).
- **Impact**: 11 legacy Python script assertions in `scripts/runTests.ts` and `scripts/run_phase_7b10_tests.ts` remain environment-blocked.
- **Resolution Provided**: Pinned dependencies are documented in `requirements.txt` (`joblib==1.4.2`, `scikit-learn==1.4.2`, `pandas==2.2.2`, `numpy==1.26.4`, `scipy==1.13.0`) for deployment targets with dual Python/Node containerization.
- **Operational Safety**: All operational server routes, UI modules, database queries, and shadow governance mechanisms run natively on Node.js/TypeScript with zero runtime Python dependency.

---

## 4. USER JOURNEYS & ACCESS CONTROL (RBAC)

The application enforces strict Role-Based Access Control (RBAC) server-side via `requireRole` and `requireAuth`:

1. **Nodal Officer (`NODAL_OFFICER`)**:
   - Authorized for operational dashboard, project package edits, gazette ingestion, and review queue approvals.
   - Institutional account: `nodal.officer@morth.gov.in` (Firebase Authentication in production; test harness password in dev mode via `AUTH_DEV_PASSWORD`).
2. **Viewer (`VIEWER`)**:
   - Authorized for read-only audit inspection across all dashboards, evidence matrices, and shadow telemetry.
   - Mutation attempts (e.g. running shadow evaluations, approving review items) are strictly blocked with **`403 Forbidden` (`UNAUTHORIZED_ACCESS`)**.
   - Institutional account: `viewer.auditor@gov.in` (Firebase Authentication in production; test harness password in dev mode via `AUTH_DEV_PASSWORD`).
3. **Session Revocation**:
   - Calling `/api/auth/logout` revokes the session token; subsequent authenticated requests return **`401 Unauthorized`**.

---

## 5. STATUTORY EVIDENCE & CIRCUIT BREAKER DISCIPLINE

All 31 operational projects are classified across the 5 canonical evidence states:
1. `COMPLETE`: Authoritative Section 3A e-Gazette and subsequent notification sequence verified. Eligible for shadow scoring.
2. `PRE_3A`: Project is legitimately at the Detailed Project Report (DPR) stage prior to initial gazette publication. **Circuit Breaker Enforced:** Corridors like `BhoomiRashi_57405` are strictly barred from shadow scoring.
3. `PARTIAL`: Incomplete statutory notification sequence.
4. `OUT_OF_BOUNDS`: Inconsistent milestone progression.
5. `MISSING_AUTHORITATIVE_EVIDENCE`: Unverified against BhoomiRashi or e-Gazette registries.

---

## 6. DEPLOYMENT & RUNTIME INVENTORY

### Environment Variables
| Variable | Description | Default / Example | Required |
| :--- | :--- | :--- | :--- |
| `PORT` | HTTP port for Express server | `3000` | Yes |
| `NODE_ENV` | Application environment | `production` | Yes |
| `FIREBASE_PROJECT_ID` | Firebase Project ID for production authentication token verification | `bhoomi-drishti` | Yes (Production) |
| `DEMO_MODE` | Allow seeded development test authentication | `false` (production) / `true` (testing) | Optional |
| `AUTH_DEV_PASSWORD` | Test password for local test harness (ignored in production) | Secure test placeholder | Dev/Test Only |

### Health Check Endpoint
- **URL**: `GET /api/health`
- **Expected Status**: `200 OK`
- **Response**: `{"status":"ok","service":"BhoomiDrishti Intelligence"}`

### Build & Run Commands
```bash
# 1. Compile client assets and server bundle
npm run build

# 2. Start production server
npm start
# Equivalent to: node dist/server.cjs
```

---

## 7. ROLLBACK & BACKUP PROCEDURES

### Database Backup
SQLite WAL mode is enabled. Automated snapshot backups are stored in `data/`:
- `data/bhoomidrishti.db` (Primary operational database)
- `data/bhoomidrishti.db.backup_*` (Pre-phase recovery checkpoints)

### Database Restore Command
```bash
# Emergency rollback to verified baseline
cp data/bhoomidrishti_backup_phase6b_1790455000.db data/bhoomidrishti.db
```

### Git Revert
```bash
# Revert to verified release commit tag
git checkout release-v1.0.0-final
```

---

## 8. STAKEHOLDER SIGN-OFF PROTOCOL

Prior to promoting candidate models or activating decision thresholds in any future release, the following approvals must be obtained:
1. **MoRTH Competent Authority (Land Acquisition Division)**: Approval of revised risk policies.
2. **NHAI Chief Technical Officer / Nodal Officer**: Sign-off on candidate model calibration report.
3. **Independent Statutory ML Auditor**: Verification of empirical sample size (minimum 10 mature Section 3D statutory outcomes).
