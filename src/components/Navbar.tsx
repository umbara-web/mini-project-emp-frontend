'use client';
import Link from 'next/link';
import { useAuth } from '../hooks/useAuth';
import { useState } from 'react';

export default function Navbar() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);

  return (
    <nav className='sticky top-0 z-40 border-b bg-white/80 backdrop-blur supports-[backdrop-filter]:bg-white/60'>
      <div className='container mx-auto flex items-center justify-between px-4 py-3'>
        <Link href='/' className='flex items-center gap-3'>
          <div className='relative flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-tr from-indigo-600 to-violet-500 font-bold text-white shadow-sm'>
            ET
            <span className='absolute -bottom-1 -right-1 h-2 w-2 rounded-full bg-emerald-400 ring-2 ring-white' />
          </div>
          <div>
            <div className='text-lg font-extrabold tracking-tight text-slate-900'>EventTribe</div>
            <div className='text-xs text-slate-500'>Event Management</div>
          </div>
        </Link>

        <div className='hidden items-center gap-6 md:flex'>
          <Link href='/events' className='text-sm text-slate-700 hover:text-indigo-600'>
            Events
          </Link>
          <Link href='/create-event' className='text-sm text-slate-700 hover:text-indigo-600'>
            Create
          </Link>
          <Link href='/dashboard' className='text-sm text-slate-700 hover:text-indigo-600'>
            Dashboard
          </Link>
          {user ? (
            <div className='flex items-center gap-3'>
              <div className='text-sm text-slate-700'>{user.name}</div>
              <button onClick={logout} className='inline-flex items-center rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50'>
                Logout
              </button>
            </div>
          ) : (
            <Link href='/login' className='inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-500'>
              Login
            </Link>
          )}
        </div>

        <div className='md:hidden'>
          <button
            aria-label='Toggle menu'
            onClick={() => setOpen((s) => !s)}
            className='inline-flex items-center justify-center rounded p-2 text-slate-600 hover:bg-slate-100'
          >
            {open ? (
              <svg
                xmlns='http://www.w3.org/2000/svg'
                className='h-6 w-6'
                fill='none'
                viewBox='0 0 24 24'
                stroke='currentColor'
              >
                <path strokeLinecap='round' strokeLinejoin='round' strokeWidth={2} d='M6 18L18 6M6 6l12 12' />
              </svg>
            ) : (
              <svg
                xmlns='http://www.w3.org/2000/svg'
                className='h-6 w-6'
                fill='none'
                viewBox='0 0 24 24'
                stroke='currentColor'
              >
                <path strokeLinecap='round' strokeLinejoin='round' strokeWidth={2} d='M4 6h16M4 12h16M4 18h16' />
              </svg>
            )}
          </button>
        </div>
      </div>

      {open && (
        <div className='border-t bg-white md:hidden'>
          <div className='space-y-2 px-4 py-3'>
            <Link href='/events' className='block text-slate-700'>
              Events
            </Link>
            <Link href='/create-event' className='block text-slate-700'>
              Create
            </Link>
            <Link href='/dashboard' className='block text-slate-700'>
              Dashboard
            </Link>
            {user ? (
              <div className='flex items-center justify-between'>
                <div className='text-slate-700'>{user.name}</div>
                <button onClick={logout} className='text-red-500'>
                  Logout
                </button>
              </div>
            ) : (
              <Link href='/login' className='block text-indigo-600'>
                Login
              </Link>
            )}
          </div>
        </div>
      )}
    </nav>
  );
}
