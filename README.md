# cobalt-hub-145

> Work in progress. This checkpoint may be incomplete or fail tests. See PLAN.md and STATUS.md before use.


A software reverse engineering (SRE) framework with a FastAPI backend and React frontend for binary decompilation.

## Quick Start

### Backend
```bash
cd backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at http://localhost:3000 and the API at http://localhost:8000.

## API Endpoints

- `GET /health` - Health check
- `POST /api/decompile` - Decompile a binary file
  - Form data: `file` (binary), `architecture` (x86/arm/mips), `mode` (16/32/64)

## Features Implemented

- ✅ FastAPI/React skeleton with binary upload and decompile endpoint
- 🔄 Vtable function call resolution (issue #516)
- 🔄 Switch statement recognition (issue #2628)
- 🔄 JMP with PUSH return address recognition (issue #5747)
- 🔄 M68000 lineA/lineF opcode support (issue #487)
- 🔄 Cross-segment string display (issue #4865)
- 🔄 Batch decompilation performance (issue #2791)

Maintainer: Alan Vo <alanvo@gmail.com>
