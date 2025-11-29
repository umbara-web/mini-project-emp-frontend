'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import useAuthStore from '@/src/stores/authStore';


export default function Navbar() {
  const {onLogout,isLoggedIn}= useAuthStore();
  const router = useRouter();

  return (
    <div>
      <Link href={'/'} className='text-2xl font-bold'>
        Event Org.
      </Link>
       <div className="flex gap-5">
        <Link href={"articles"} className="hover:text-red-400">
          Articles
        </Link>

        <Link
          href={isLoggedIn ? "/dashboard" : "/login"}
          className="hover:text-red-400"
        >
          Dashboard
        </Link>
      </div>
      <Link href={'/login'}>
        login
      </Link>
      <Link href={'/register'}>
        register
      </Link>
    </div>
  );
}