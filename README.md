# BHOOMI-DRISHTI (भूमि-दृष्टि)

**Statutory Land Acquisition Intelligence & Delay Risk Monitoring Platform**  
*Smart India Hackathon 2026 (Problem Statement: SIH26017) — Ministry of Road Transport & Highways (MoRTH) / National Highways Authority of India (NHAI)*

---

## Overview

**BHOOMI-DRISHTI** is an AI-driven decision-support and predictive analytics platform designed to detect, diagnose, and mitigate land acquisition delays across national highway corridors under the **National Highways Act, 1956** (Sections **3A**, **3D**, **3G**, and **3H**) and the **RFCTLARR Act, 2013**.

By integrating statutory provenance records from the **MoRTH BhoomiRashi portal**, point-in-time historical feature reconstruction, supervised machine learning inference, and institutional model governance, the platform enables Competent Authorities for Land Acquisition (CALA), Nodal Officers, and Project Auditors to identify and resolve bottlenecks before physical construction is stalled.

---

## Key Features

- **Supervised ML Delay Risk Engine (`BHOOMI-DRISHTI-ML-V1.0`)**: Computes acquisition delay probabilities (0–100%), risk tiers (`HIGH`, `MEDIUM`, `LOW`), and schedule variance (in months) across 31 national highway corridors using a Class-Weighted Random Forest classifier (`ROC-AUC: 0.883`, `Accuracy: 88.0%`).
- **Shadow Model Governance (`BHOOMI-DRISHTI-ML-V2.0-SHADOW`)**: 11-tab governance workspace evaluating candidate longitudinal models in strict non-operational isolation with PSI/KS drift monitoring, McNemar's test, paired bootstrap confidence intervals, and a Pre-3A statutory circuit breaker.
- **Statutory Data Hub & Evidence Workspace**: Connects to official MoRTH BhoomiRashi endpoints, performs SHA-256 change detection, classifies corridors into 5 statutory evidence states (`COMPLETE`, `PRE_3A`, `PARTIAL`, `OUT_OF_BOUNDS`, `MISSING_AUTHORITATIVE_EVIDENCE`), and provides a 6-stage atomic CSV ingestion pipeline with formula injection defanging and Excel-compatible UTF-8 exports.
- **"What-If" Policy Simulator**: Counterfactual simulation engine allowing officers to test interventions—such as accelerating compensation disbursement, resolving Section 3G arbitration, vacating court stays, or expediting forest clearances—and quantify risk reduction and months saved.
- **National GIS Risk Command Center**: Interactive OpenStreetMap & Leaflet geospatial dashboard plotting corridor alignments, package markers, and district-level bottlenecks across India.
- **Institutional RBAC & Audit Trail**: Role-based access control (`NODAL_OFFICER`, `AUDITOR`, `VIEWER`) backed by Google Firebase Authentication, SIH Evaluator Demo Mode, and an immutable cryptographic audit log.

---

## Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS 4, Recharts, Leaflet (OpenStreetMap), Lucide Icons
- **Backend**: Node.js, Express, TypeScript (`tsx` / `esbuild`)
- **Database**: SQLite (`node:sqlite` in WAL mode)
- **Machine Learning**: Python (`scikit-learn`, `joblib`) + TypeScript ML Prediction Bridge & Shadow Runner
- **Authentication & Security**: Firebase Authentication (`jose` JWKS verification), Server-Side RBAC, Rate Limiting, CSP Headers

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy environment configuration
cp .env.example .env

# 3. Start development server (http://localhost:3000)
npm run dev
