# 🛰️ BHOOMI-DRISHTI

> **Predictive Analytics System for Early Detection of Land Acquisition Delays**  
> *Smart India Hackathon 2026 (Problem Statement: SIH26017) — Government of India*

---

## 📌 Overview

**BHOOMI-DRISHTI** is an AI-driven monitoring and decision-support platform designed to forecast, diagnose, and mitigate land acquisition delays across national infrastructure projects.

By continuously analyzing statutory milestones under the National Highways Act 1956 and RFCTLARR Act 2013 (Section 3A, 3D, 3G, 3H notifications, compensation disbursements, judicial references, and environmental clearances), the platform detects bottlenecks months before physical construction is impacted.

---

## ✨ Key Features

- **🎯 Predictive Risk Scoring Engine**: Calculates acquisition delay probabilities (0–100%) and projected schedule variance (in months) using multi-factor ML scoring calibrated against historical statutory timelines.
- **🔍 Explainable AI & Bottleneck Attribution**: Breaks down exact root causes driving project risk (e.g., judicial stays, compensation disbursement backlogs, mutation records, and pending Stage-1/Stage-2 forest clearances).
- **🧪 "What-If" Policy Simulator**: Interactive counterfactual simulator enabling authorities to test intervention outcomes—such as special disbursement camps or vacating judicial stays—to quantify risk reduction and time saved prior to deployment.
- **🗺️ Interactive GIS Risk Map**: Geospatial corridor view displaying project locations, risk tiers (High / Medium / Low), stage progression, and district-level breakdown across India.
- **🔄 DataHub Ingestion & Change Detection**: Automated ingestion pipeline supporting authentic BhoomiRashi and LACRRIS data sources, with cryptographic hashing (`SHA-256`) for immutable audit trails and real-time alerts.
- **📄 Executive Reports & Briefings**: Automated statutory briefing generator producing one-click ministerial digests, district review dossiers, and printable PDF inspection reports.

---

## 🏗️ Architecture & Tech Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS, Lucide Icons, Motion animations
- **Charts & Data Visuals**: Recharts, D3.js
- **Backend API Server**: Node.js, Express, TypeScript (`tsx` in dev, `esbuild` for production CommonJS bundle)
- **Database**: SQLite (high-performance embedded storage with WAL mode and parameterized prepared statements)
- **Security**: Strict input sanitation, parameterized SQL queries, zero client-side credentials, and standard HTTP security headers

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ or 20+
- npm 9+

### 1. Clone & Install
```bash
git clone https://github.com/your-username/bhoomi-drishti.git
cd bhoomi-drishti
npm install
```

### 2. Environment Setup
Copy the example environment configuration:
```bash
cp .env.example .env
```
*(No external secrets required for standard offline SQLite operation)*

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Testing & Verification

Run the built-in comprehensive verification and quality test suite:
```bash
npm test
```
The test suite validates:
- Data integrity & authentic BhoomiRashi source verification (Project 60940)
- Single source of truth consistency (total project counts and risk aggregations)
- Deterministic cryptographic hashing & change detection
- ML delay prediction & variance calculation boundaries
- "What-If" counterfactual engine immutability and safe clamping
- SQL injection prevention and API parameter sanitization

To run static type-checking:
```bash
npm run lint
```

---

## 📦 Production Build

Build both the client-side SPA assets and the server bundle:
```bash
npm run build
```

Start the production server:
```bash
npm start
```

---

## 📂 Project Structure

```
├── data/                     # SQLite database files and persistent storage
├── scripts/
│   └── runTests.ts          # Comprehensive automated quality test suite
├── src/
│   ├── components/          # React UI components (Dashboard, Map, Simulator, Reports)
│   ├── server/              # Server-side business logic & database
│   │   ├── datahub/         # Ingestion adapters & change detection engine
│   │   ├── database.ts      # Authoritative SQLite storage & query services
│   │   ├── mlModel.ts       # Delay prediction & feature attribution algorithms
│   │   └── predictionService.ts # "What-If" simulation logic
│   ├── types.ts             # TypeScript interfaces and domain schemas
│   ├── App.tsx              # Main application shell
│   └── main.tsx             # Application bootstrap
├── index.html               # Entry HTML template
├── metadata.json            # Application platform metadata
├── package.json             # NPM dependencies & scripts
├── server.ts                # Express server entry point & API routes
└── vite.config.ts           # Vite build configuration
```

---

## 📜 License

This project is developed as part of **Smart India Hackathon 2026** (Problem Statement SIH26017).  
Distributed under the **MIT License**.
