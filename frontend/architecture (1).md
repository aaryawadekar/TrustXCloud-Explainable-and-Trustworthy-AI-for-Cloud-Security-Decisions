# Frontend Architecture
## Explainable AI for Cloud Security Dashboard

**Scope:** Frontend only  
**Framework:** Next.js + TypeScript

---

# 1. Architecture Overview

```text
                         BACKEND SYSTEM
                               │
                    REST API / JSON Responses
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│                     NEXT.JS FRONTEND                     │
│                                                          │
│  ┌──────────────┐       ┌───────────────────────────┐    │
│  │ App Router   │──────▶│ Page Components           │    │
│  └──────────────┘       └─────────────┬─────────────┘    │
│                                       │                  │
│                         ┌─────────────▼─────────────┐    │
│                         │ Feature Components        │    │
│                         │ Dashboard / Alerts / XAI  │    │
│                         └─────────────┬─────────────┘    │
│                                       │                  │
│                         ┌─────────────▼─────────────┐    │
│                         │ TanStack Query            │    │
│                         │ Server-state management   │    │
│                         └─────────────┬─────────────┘    │
│                                       │                  │
│                         ┌─────────────▼─────────────┐    │
│                         │ API Service Layer         │    │
│                         └───────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

---

# 2. High-Level Component Architecture

```text
App
│
├── Dashboard
│   ├── Overview Cards
│   ├── Security Trend Chart
│   ├── Risk Distribution
│   └── Recent Alerts
│
├── Alerts
│   ├── Alert Filters
│   ├── Alert Table
│   └── Pagination
│
├── Event Details
│   ├── Event Summary
│   ├── Risk Score
│   ├── XAI Explanation
│   ├── Event Metadata
│   ├── IAM Context
│   └── Event Timeline
│
└── Model Performance
    ├── Metric Cards
    └── Performance Charts
```

---

# 3. Recommended Project Structure

```text
src/
│
├── app/
│   ├── layout.tsx
│   ├── page.tsx
│   │
│   ├── dashboard/
│   │   └── page.tsx
│   │
│   ├── alerts/
│   │   ├── page.tsx
│   │   └── [id]/
│   │       └── page.tsx
│   │
│   ├── activity/
│   │   └── page.tsx
│   │
│   └── models/
│       └── page.tsx
│
├── components/
│   │
│   ├── ui/
│   │   └── shadcn components
│   │
│   ├── layout/
│   │   ├── sidebar.tsx
│   │   ├── header.tsx
│   │   └── app-shell.tsx
│   │
│   ├── dashboard/
│   │   ├── metric-card.tsx
│   │   ├── security-trend-chart.tsx
│   │   ├── risk-distribution-chart.tsx
│   │   └── recent-alerts.tsx
│   │
│   ├── alerts/
│   │   ├── alerts-table.tsx
│   │   ├── alert-filters.tsx
│   │   └── risk-badge.tsx
│   │
│   ├── event/
│   │   ├── event-summary.tsx
│   │   ├── event-metadata.tsx
│   │   └── event-timeline.tsx
│   │
│   └── xai/
│       ├── explanation-panel.tsx
│       ├── feature-impact-chart.tsx
│       ├── factor-card.tsx
│       └── explanation-summary.tsx
│
├── services/
│   ├── api-client.ts
│   ├── dashboard.service.ts
│   ├── events.service.ts
│   ├── alerts.service.ts
│   └── analysis.service.ts
│
├── hooks/
│   ├── use-dashboard.ts
│   ├── use-events.ts
│   ├── use-alerts.ts
│   └── use-analysis.ts
│
├── types/
│   ├── event.ts
│   ├── alert.ts
│   ├── analysis.ts
│   └── dashboard.ts
│
├── lib/
│   ├── utils.ts
│   └── constants.ts
│
└── providers/
    └── query-provider.tsx
```

---

# 4. Routing Architecture

| Route | Purpose |
|---|---|
| `/dashboard` | Security overview |
| `/alerts` | Browse and filter alerts |
| `/alerts/[id]` | Investigate a specific alert |
| `/activity` | IAM/security activity |
| `/models` | Model performance |

The event or alert details page is the central research-facing screen.

---

# 5. Data Flow Architecture

## Dashboard Flow

```text
Dashboard Page
      │
      ▼
useDashboard()
      │
      ▼
TanStack Query
      │
      ▼
dashboard.service.ts
      │
      ▼
GET /dashboard/overview
      │
      ▼
Backend API
      │
      ▼
JSON Response
      │
      ▼
Dashboard Components
```

## Event Investigation Flow

```text
User clicks alert
       │
       ▼
/alerts/{id}
       │
       ├───────────────┐
       ▼               ▼
GET Event          GET Analysis
       │               │
       ▼               ▼
Event Data       ML + XAI Data
       │               │
       └───────┬───────┘
               ▼
       Investigation Page
               │
      ┌────────┼─────────┐
      ▼        ▼         ▼
   Summary  Timeline  XAI Panel
```

---

# 6. API Layer Architecture

The frontend should not directly scatter `fetch()` calls throughout UI components.

Use a dedicated service layer.

## API Client

```text
services/api-client.ts
```

Responsibilities:

- Base URL configuration
- HTTP requests
- Error normalization
- Response parsing

## Domain Services

```text
dashboard.service.ts
events.service.ts
alerts.service.ts
analysis.service.ts
```

Example conceptual separation:

```text
UI Component
    ↓
Custom Hook
    ↓
Domain Service
    ↓
API Client
    ↓
Backend
```

This makes backend API changes easier to manage.

---

# 7. State Management

## Server State
Use **TanStack Query** for:

- Events
- Alerts
- Dashboard statistics
- XAI analysis
- Model performance

## Local UI State
Use React state for:

- Open dialogs
- Selected filters
- Table controls
- View preferences

Avoid introducing Redux unless the project grows significantly.

---

# 8. Type Architecture

Use TypeScript interfaces to define backend contracts.

## Example Security Event

```ts
interface SecurityEvent {
  id: string;
  timestamp: string;
  user: string;
  iamRole?: string;
  eventName: string;
  service: string;
  sourceIp: string;
  region?: string;
  riskScore: number;
  classification: "normal" | "suspicious" | "high_risk";
}
```

## Example XAI Factor

```ts
interface ExplanationFactor {
  feature: string;
  impact: number;
}
```

## Example Analysis

```ts
interface SecurityAnalysis {
  eventId: string;
  riskScore: number;
  classification: string;
  confidence: number;
  explanation: {
    summary: string;
    topFactors: ExplanationFactor[];
  };
}
```

---

# 9. XAI Visualization Architecture

This is the most important frontend module.

```text
Backend SHAP/LIME Output
          │
          ▼
Analysis Service
          │
          ▼
useAnalysis()
          │
          ▼
ExplanationPanel
          │
    ┌─────┴──────┐
    ▼            ▼
Summary      Feature Chart
                 │
          ┌──────┴──────┐
          ▼             ▼
    Positive Impact  Negative Impact
```

## Design Requirements

The visualization must communicate:

- Which factors increased risk
- Which factors reduced risk
- Relative contribution
- Human-readable feature names

The frontend must **visualize** explanations rather than calculate SHAP values.

---

# 10. Error and Loading Architecture

Every API-driven screen should handle:

```text
Loading
   ↓
Success → Render data
   ↓
Error → Error state + retry
```

Required UI states:

- Skeleton loading
- Empty data
- API error
- Network failure
- Missing event

---

# 11. Chart Architecture

Use Recharts for standard visualizations.

| Visualization | Recommended Chart |
|---|---|
| Security events over time | Line/Area |
| Risk distribution | Bar/Pie |
| Top threat types | Bar |
| XAI factor impact | Horizontal bar |
| Model metrics | Bar/Radar |
| Event activity | Timeline |

Avoid overly complex visualizations unless they improve explainability.

---

# 12. Design System

## Component Library
Use **shadcn/ui** as the base component system.

Core components:

- Card
- Table
- Badge
- Button
- Tabs
- Sheet
- Dialog
- Select
- Input
- Skeleton
- Tooltip

## Icons
Use Lucide React.

## Design Principle

```text
Information clarity
        >
Visual decoration
```

This is a security and research dashboard, not a generic admin panel.

---

# 13. Environment Configuration

```text
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
```

The API URL must not be hard-coded inside components.

For deployment:

```text
Development
  → Local backend

Production
  → Deployed backend URL
```

---

# 14. Frontend / Backend Contract

The backend team should provide:

- Stable endpoint definitions
- Request parameters
- Response schemas
- Error formats
- Authentication requirements, if any
- Sample JSON responses

The frontend team should provide:

- Required data fields
- Pagination requirements
- Filter/query requirements
- XAI visualization data contract

A shared API contract should be agreed upon before integration.

---

# 15. Development Sequence

## Stage 1 — Foundation

```text
Next.js
→ TypeScript
→ Tailwind
→ shadcn/ui
→ Application shell
```

## Stage 2 — Mock Data

```text
Mock JSON
→ Dashboard
→ Alerts table
→ Alert details
```

## Stage 3 — XAI Interface

```text
Mock explanation data
→ Explanation panel
→ Feature impact chart
→ Explanation summary
```

## Stage 4 — Backend Integration

```text
API client
→ Services
→ TanStack Query
→ Real data
```

## Stage 5 — Production Polish

```text
Error states
→ Loading states
→ Responsiveness
→ Performance
→ Testing
```

---

# 16. Final Frontend Architecture Summary

```text
┌─────────────────────────────────────────────┐
│                 NEXT.JS APP                 │
│                                             │
│  Pages / Routes                             │
│       │                                     │
│       ▼                                     │
│  Feature Components                         │
│  ├── Dashboard                              │
│  ├── Alerts                                 │
│  ├── Investigation                          │
│  └── XAI Visualization                      │
│       │                                     │
│       ▼                                     │
│  Custom Hooks + TanStack Query              │
│       │                                     │
│       ▼                                     │
│  Domain API Services                        │
│       │                                     │
│       ▼                                     │
│  FastAPI / Backend REST API                 │
└─────────────────────────────────────────────┘
```

# Core Architectural Principle

> **The frontend is responsible for converting complex cloud-security and AI/XAI outputs into an interface that a human can quickly understand and investigate.**
