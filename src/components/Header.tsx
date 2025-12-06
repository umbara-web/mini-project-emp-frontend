'use client';

import React, { useEffect, useState } from 'react';
import {
  Search,
  ShoppingBag,
  Bell,
  ChevronDown,
  User,
  LogOut,
  Sparkles,
} from 'lucide-react';
import { User as UserType } from '../types/types';
import { useRouter } from 'next/navigation';
import { authService } from '../services/authServices';

interface HeaderProps {
  user?: UserType;
}

export default function Header({ user }: HeaderProps) {
  const router = useRouter();
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const [sessionUser, setSessionUser] = useState<UserType | undefined>(
    undefined
  );

  useEffect(() => {
    const u = authService.getCurrentUser();
    if (u) setSessionUser(u as UserType);
  }, []);

  const currentUser = (user ?? sessionUser) as UserType | undefined;

  const handleLogout = () => {
    authService.logout();
    router.push('/');
  };

  return (
    <header className='sticky top-0 z-50 h-20 border-b border-gray-100 bg-white'>
      <div className='container mx-auto flex h-full items-center justify-between gap-4 px-4'>
        {/* Logo */}
        <div
          className='flex cursor-pointer items-center gap-2'
          onClick={() => router.push('/')}
        >
          <Sparkles className='h-8 w-8 text-blue-600' />
          <span className='hidden text-2xl font-bold text-gray-900 md:block'>
            Evently
          </span>
        </div>

        {/* Search Bar */}
        <div className='hidden max-w-1/2 flex-1 md:block'>
          <div className='relative'>
            <Search className='absolute top-1/2 left-4 h-5 w-5 -translate-y-1/2 text-gray-400' />
            <input
              type='text'
              placeholder='Search events'
              className='w-full rounded-full border border-gray-200 py-3 pr-4 pl-11 text-sm transition-all focus:border-blue-500 focus:ring-4 focus:ring-blue-50 focus:outline-none'
            />
          </div>
        </div>

        {/* Right Actions */}
        <div className='flex items-center gap-6'>
          <div className='relative cursor-pointer'>
            <ShoppingBag className='h-6 w-6 text-gray-700' />
            <span className='absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white'>
              1
            </span>
          </div>

          {/* User Dropdown */}
          <div className='relative'>
            <button
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              className='flex items-center gap-3 focus:outline-none'
            >
              <div className='h-10 w-10 overflow-hidden rounded-full border border-gray-200 bg-gray-200'>
                {currentUser?.avatar ? (
                  <img
                    src={currentUser.avatar || ''}
                    alt={currentUser?.name || 'User'}
                    className='h-full w-full object-cover'
                  />
                ) : (
                  <div className='flex h-full w-full items-center justify-center bg-blue-100 text-lg font-bold text-blue-600'>
                    {currentUser?.name?.charAt(0) || '?'}
                  </div>
                )}
              </div>
              <div className='hidden items-center gap-2 md:flex'>
                <span className='font-medium text-gray-900'>
                  {currentUser?.name || 'Guest'}
                </span>
                <ChevronDown
                  className={`h-4 w-4 text-gray-500 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`}
                />
              </div>
            </button>

            {/* Dropdown Menu */}
            {isDropdownOpen && (
              <div className='animate-fade-in absolute top-full right-0 mt-2 w-56 origin-top-right rounded-xl border border-gray-100 bg-white py-2 shadow-xl'>
                <div className='border-b border-gray-50 px-4 py-3 md:hidden'>
                  <p className='font-semibold text-gray-900'>
                    {currentUser?.name || 'Guest'}
                  </p>
                  <p className='truncate text-xs text-gray-500'>
                    {currentUser?.email || ''}
                  </p>
                </div>

                <button
                  onClick={() => {
                    router.push('/Profile');
                    setIsDropdownOpen(false);
                  }}
                  className='flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50'
                >
                  <User size={16} /> Profile
                </button>
                <button
                  onClick={() => {
                    router.push('/dashboard');
                    setIsDropdownOpen(false);
                  }}
                  className='flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50'
                >
                  <ShoppingBag size={16} /> Borrowed List
                </button>

                <div className='my-1 border-t border-gray-100'></div>

                <button
                  onClick={() => {
                    router.push('/');
                    setIsDropdownOpen(false);
                  }}
                  className='flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50'
                >
                  <LogOut size={16} /> Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
