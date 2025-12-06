'use client';
import { useEffect, useState } from 'react';

export default function CountdownUpload({
  expiresAt,
  onExpire,
}: {
  expiresAt: string;
  onExpire?: () => void;
}) {
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    const target = new Date(expiresAt).getTime();
    function tick() {
      const now = Date.now();
      const diff = Math.max(0, target - now);
      setRemaining(diff);
      if (diff === 0) onExpire?.();
    }
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [expiresAt, onExpire]);

  const seconds = Math.floor((remaining / 1000) % 60);
  const minutes = Math.floor((remaining / 1000 / 60) % 60);
  const hours = Math.floor(remaining / 1000 / 60 / 60);

  return (
    <div className='inline-flex items-center gap-2 text-sm text-gray-700'>
      <span className='font-medium'>Unggah bukti pembayaran dalam:</span>
      <span className='rounded bg-gray-100 px-2 py-1'>
        {String(hours).padStart(2, '0')}:{String(minutes).padStart(2, '0')}:
        {String(seconds).padStart(2, '0')}
      </span>
    </div>
  );
}
