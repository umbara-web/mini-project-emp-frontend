'use client';
import { useState, useEffect } from 'react';
import useDebounce from '../hooks/useDebounce';

type Props = {
  onSearch?: (q: string) => void;
};

export default function SearchBar({ onSearch }: Props) {
  const [q, setQ] = useState('');
  const debounced = useDebounce(q, 400);

  useEffect(() => {
    onSearch?.(debounced);
  }, [debounced, onSearch]);

  return (
    <div className='w-full max-w-xl'>
      <label className='relative block'>
        <span className='absolute inset-y-0 left-3 flex items-center text-gray-400'>
          <svg
            xmlns='http://www.w3.org/2000/svg'
            className='h-5 w-5'
            viewBox='0 0 20 20'
            fill='currentColor'
          >
            <path
              fillRule='evenodd'
              d='M12.9 14.32a8 8 0 111.414-1.414l4.387 4.386a1 1 0 01-1.414 1.415l-4.387-4.387zM8 14a6 6 0 100-12 6 6 0 000 12z'
              clipRule='evenodd'
            />
          </svg>
        </span>
        <input
          aria-label='Cari acara'
          type='search'
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder='Cari acara, kategori, atau lokasi...'
          className='focus:ring-primary bg-surface w-full rounded-full border border-transparent px-12 py-3 shadow focus:ring-2 focus:outline-none'
        />
        {q && (
          <button
            onClick={() => setQ('')}
            className='absolute top-1/2 right-3 -translate-y-1/2 text-sm text-gray-500'
          >
            Clear
          </button>
        )}
      </label>
      <div className='mt-3 flex flex-wrap gap-2'>
        <button className='bg-surface text-muted rounded-full border border-gray-200 px-3 py-1 text-sm shadow-sm'>
          Semua Kategori
        </button>
        <button className='bg-surface text-muted rounded-full border border-gray-200 px-3 py-1 text-sm shadow-sm'>
          Dalam Kota
        </button>
        <button className='bg-surface text-muted rounded-full border border-gray-200 px-3 py-1 text-sm shadow-sm'>
          Gratis
        </button>
      </div>
    </div>
  );
}
