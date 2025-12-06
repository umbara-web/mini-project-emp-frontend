'use client';
import { useEffect, useState } from 'react';
import { fetchEvents } from '../../lib/api';

export default function Dashboard() {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    fetchEvents().then((d) => setEvents(d));
  }, []);

  return (
    <div className='container mx-auto p-4'>
      <h2 className='mb-4 text-2xl font-bold'>Dasbor Penyelenggara</h2>
      <section className='mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3'>
        <div className='rounded border p-4'>
          <h3 className='font-semibold'>Statistik</h3>
          <p className='text-sm text-gray-600'>Acara: {events.length}</p>
          <p className='text-sm text-gray-600'>Pendapatan (mock): Rp0</p>
        </div>
        <div className='rounded border p-4 lg:col-span-2'>
          <h3 className='mb-2 font-semibold'>Acara Anda</h3>
          <ul>
            {events.map((e) => (
              <li key={e.id} className='border-b py-2'>
                {e.title} — {new Date(e.date).toLocaleDateString()}
              </li>
            ))}
          </ul>
        </div>
      </section>
      <section>
        <h3 className='mb-2 font-semibold'>Transaksi Terbaru</h3>
        <div className='text-sm text-gray-600'>
          (Daftar transaksi mock akan muncul di sini)
        </div>
      </section>
    </div>
  );
}
