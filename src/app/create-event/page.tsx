'use client';
import { useState } from 'react';
import { createEvent } from '../../lib/api';

export default function CreateEventPage() {
  const [title, setTitle] = useState('');
  const [date, setDate] = useState('');
  const [location, setLocation] = useState('');
  const [price, setPrice] = useState<number>(0);
  const [seats, setSeats] = useState<number>(0);
  const [desc, setDesc] = useState('');
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title) return alert('Judul diperlukan');
    setSaving(true);
    await createEvent({
      title,
      date,
      location,
      price,
      seats,
      description: desc,
    });
    setSaving(false);
    alert('Acara berhasil dibuat (mock)');
  }

  return (
    <div className='container mx-auto p-4'>
      <h2 className='mb-4 text-2xl font-bold'>Buat Acara</h2>
      <form
        onSubmit={handleSubmit}
        className='grid max-w-2xl grid-cols-1 gap-4'
      >
        <input
          className='rounded border px-3 py-2'
          placeholder='Judul acara'
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <input
          type='datetime-local'
          className='rounded border px-3 py-2'
          value={date}
          onChange={(e) => setDate(e.target.value)}
        />
        <input
          className='rounded border px-3 py-2'
          placeholder='Lokasi'
          value={location}
          onChange={(e) => setLocation(e.target.value)}
        />
        <input
          type='number'
          className='rounded border px-3 py-2'
          placeholder='Harga (Rupiah)'
          value={price}
          onChange={(e) => setPrice(Number(e.target.value))}
        />
        <input
          type='number'
          className='rounded border px-3 py-2'
          placeholder='Kursi tersedia'
          value={seats}
          onChange={(e) => setSeats(Number(e.target.value))}
        />
        <textarea
          className='rounded border px-3 py-2'
          placeholder='Deskripsi'
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
        />
        <div className='flex gap-2'>
          <button className='btn-primary disabled:opacity-60' disabled={saving}>
            {saving ? 'Menyimpan...' : 'Simpan'}
          </button>
          <button
            type='button'
            className='rounded border px-4 py-2'
            onClick={() => {
              if (!confirm('Batalkan pembuatan acara?')) return;
              setTitle('');
              setDate('');
              setLocation('');
              setPrice(0);
              setSeats(0);
              setDesc('');
            }}
          >
            Batal
          </button>
        </div>
      </form>
    </div>
  );
}
