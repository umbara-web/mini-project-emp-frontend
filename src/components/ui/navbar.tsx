'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function Navbar() {
  const router = useRouter();

  return (
    <div>
      <Link href={'/'} className='text-2xl font-bold'>
        Event Org.
      </Link>
      
      <Link href={'/login'}>
        login
      </Link>
      <Link href={'/register'}>
        register
      </Link>
    </div>
  );
}