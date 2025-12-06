'use client';

// import { useRouter } from 'next/router';
import { Sparkles } from 'lucide-react';
import Link from 'next/link';

export default function Footer() {
  // const router = useRouter();
  return (
    <footer className='mt-16 border-t border-slate-200 bg-white'>
      <div className='relative'>
        <div className='bg-linier-to-r pointer-events-none absolute -top-6 left-1/2 h-12 w-48 -translate-x-1/2 rounded-full from-indigo-500/40 to-violet-500/40 blur-2xl' />
      </div>
      <div className='container mx-auto px-4 py-10'>
        <div className='grid grid-cols-2 gap-8 md:grid-cols-4'>
          <div className='col-span-2 md:col-span-1'>
            <Link href='/' className='mb-3 flex items-center gap-2'>
              {/* Logo */}
              {/* <div
                className='flex cursor-pointer items-center gap-2'
                onClick={() => router.push('/')}
              > */}
              <Sparkles className='h-8 w-8 text-blue-600' />
              <span className='hidden text-2xl font-bold text-gray-900 md:block'>
                Evently
              </span>
              {/* </div> */}
            </Link>
            <p className='text-sm text-slate-600'>
              Platform untuk menemukan dan mengelola acara terbaik di sekitar
              Anda.
            </p>
          </div>

          <div>
            <h4 className='text-xs font-semibold tracking-wide text-slate-500 uppercase'>
              Produk
            </h4>
            <ul className='mt-3 space-y-2 text-sm text-slate-600'>
              <li>
                <a className='hover:text-indigo-600' href='/events'>
                  Jelajahi Event
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='/create-event'>
                  Buat Event
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='/dashboard'>
                  Dashboard
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h4 className='text-xs font-semibold tracking-wide text-slate-500 uppercase'>
              Perusahaan
            </h4>
            <ul className='mt-3 space-y-2 text-sm text-slate-600'>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Tentang
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Karir
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Kontak
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h4 className='text-xs font-semibold tracking-wide text-slate-500 uppercase'>
              Dukungan
            </h4>
            <ul className='mt-3 space-y-2 text-sm text-slate-600'>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Bantuan
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Kebijakan Privasi
                </a>
              </li>
              <li>
                <a className='hover:text-indigo-600' href='#'>
                  Syarat & Ketentuan
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className='mt-10 flex flex-col items-center justify-between gap-4 border-t border-slate-200 pt-6 md:flex-row'>
          <p className='text-xs text-slate-500'>
            © {new Date().getFullYear()} EventTribe. All rights reserved.
          </p>
          <div className='flex items-center gap-3'>
            <a
              aria-label='Twitter'
              href='#'
              className='inline-flex h-9 w-9 items-center justify-center rounded-full border border-slate-200 text-slate-600 hover:bg-slate-50'
            >
              <svg
                xmlns='http://www.w3.org/2000/svg'
                viewBox='0 0 24 24'
                fill='currentColor'
                className='h-4 w-4'
              >
                <path d='M19.633 7.997c.013.18.013.36.013.54 0 5.49-4.181 11.819-11.819 11.819-2.35 0-4.532-.69-6.37-1.876.33.038.647.051.99.051a8.36 8.36 0 0 0 5.182-1.787 4.18 4.18 0 0 1-3.902-2.897c.256.038.513.064.782.064.378 0 .756-.051 1.108-.141A4.173 4.173 0 0 1 2.84 9.122v-.051c.564.316 1.22.513 1.915.538A4.168 4.168 0 0 1 2.7 6.41c0-.775.205-1.484.564-2.105a11.86 11.86 0 0 0 8.6 4.36 4.706 4.706 0 0 1-.103-.957 4.17 4.17 0 0 1 7.214-2.852 8.24 8.24 0 0 0 2.647-1.007 4.18 4.18 0 0 1-1.832 2.304 8.345 8.345 0 0 0 2.4-.64 8.965 8.965 0 0 1-2.458 2.385Z' />
              </svg>
            </a>
            <a
              aria-label='Instagram'
              href='#'
              className='inline-flex h-9 w-9 items-center justify-center rounded-full border border-slate-200 text-slate-600 hover:bg-slate-50'
            >
              <svg
                xmlns='http://www.w3.org/2000/svg'
                viewBox='0 0 24 24'
                fill='currentColor'
                className='h-4 w-4'
              >
                <path d='M7 2C4.243 2 2 4.243 2 7v10c0 2.757 2.243 5 5 5h10c2.757 0 5-2.243 5-5V7c0-2.757-2.243-5-5-5H7zm10 2a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h10zm-5 3a5 5 0 1 0 .001 10.001A5 5 0 0 0 12 7zm0 2a3 3 0 1 1-.001 6.001A3 3 0 0 1 12 9zm5.5-3a1 1 0 1 0 0 2 1 1 0 0 0 0-2z' />
              </svg>
            </a>
            <a
              aria-label='LinkedIn'
              href='#'
              className='inline-flex h-9 w-9 items-center justify-center rounded-full border border-slate-200 text-slate-600 hover:bg-slate-50'
            >
              <svg
                xmlns='http://www.w3.org/2000/svg'
                viewBox='0 0 24 24'
                fill='currentColor'
                className='h-4 w-4'
              >
                <path d='M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.447-2.136 2.943v5.663H9.351V9h3.414v1.561h.049c.476-.9 1.637-1.852 3.369-1.852 3.604 0 4.269 2.372 4.269 5.455v6.288zM5.337 7.433a2.062 2.062 0 1 1 0-4.124 2.062 2.062 0 0 1 0 4.124zM6.999 20.452H3.673V9h3.326v11.452z' />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
