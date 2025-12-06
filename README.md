Frontend MVP (Event Management)

Quick start (frontend only):

1. Install deps

```bash
cd frontend
npm install
```

2. Run dev server

```bash
npm run dev
```

What I added (frontend):

- Landing page with search and event list (debounced search hook).
- Event detail page with purchase button and 2-hour upload countdown UI.
- Create event page for organizers (mocked create).
- Basic dashboard for organizers with event list and stats placeholder.
- Mock API in `src/lib/api.ts` to provide demo data.
- `useAuth` mock provider for role-based UI testing.
- Confirmation dialog patterns and responsive layouts using Tailwind CSS.
- Unit tests stubs for `useDebounce` and `SearchBar` (`src/__tests__`).

Notes & next steps:

- Tests require adding `jest` and `@testing-library/react` dependencies and config.
- Wire up real API endpoints and secure protected routes using `useAuth` and NextAuth for production.
- Add SQL transaction logic and backend integration for purchase flow, expiry jobs, and email notifications.
  This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
