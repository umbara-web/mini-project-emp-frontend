'use client';

import React from 'react';
import Link from 'next/link';
import { Event, TransactionStatus } from '../types/types';
import { formatRupiah } from '../../lib/utils';
import { MapPin, Star } from 'lucide-react';
import { useStore } from './Store';

export const EventCard: React.FC<{ event: Event }> = ({ event }) => {
  const { currentUser, toggleInterest } = useStore();
  const dateObj = new Date(event.startDate);
  const month = dateObj
    .toLocaleString('default', { month: 'short' })
    .toUpperCase();
  const day = dateObj.getDate();

  const isInterested = currentUser?.interestedEventIds?.includes(event.id);

  const handleInterestClick = (e: React.MouseEvent) => {
    e.preventDefault(); // Prevent link navigation
    e.stopPropagation();
    if (currentUser) {
      toggleInterest(event.id);
    } else {
      alert('Please log in to add this event to your interested list.');
    }
  };

  return (
    <div className='group flex h-full flex-col overflow-hidden rounded-xl border border-gray-100 bg-white shadow-sm transition-shadow duration-300 hover:shadow-md'>
      <div className='relative h-48 overflow-hidden'>
        <img
          className='h-full w-full transform object-cover transition-transform duration-500 group-hover:scale-105'
          src={event.image}
          alt={event.title}
        />
        <div className='absolute top-3 left-3 min-w-[50px] rounded bg-white/90 px-3 py-1 text-center shadow-sm backdrop-blur-sm'>
          <div className='text-primary-600 text-xs font-bold uppercase'>
            {month}
          </div>
          <div className='text-lg font-bold text-gray-900'>{day}</div>
        </div>
        <button
          onClick={handleInterestClick}
          className='absolute right-3 bottom-3 rounded-full bg-white/90 p-1.5 shadow-sm backdrop-blur-sm transition-colors hover:bg-white'
        >
          <Star
            className={`h-4 w-4 transition-colors ${isInterested ? 'fill-current text-yellow-400' : 'text-gray-400 hover:text-yellow-400'}`}
          />
        </button>
        <div className='absolute bottom-3 left-3 rounded bg-[#facc15] px-2 py-0.5 text-[10px] font-bold text-[#1e1e2e] uppercase'>
          {event.category}
        </div>
      </div>
      <div className='flex flex-1 flex-col p-4'>
        <h3 className='hover:text-primary-600 mb-2 line-clamp-2 min-h-[40px] text-base leading-tight font-bold text-gray-900 transition-colors'>
          <Link href={`/events/${event.id}`}>{event.title}</Link>
        </h3>
        <div className='mb-3 flex items-center text-xs text-gray-500'>
          <MapPin className='mr-1 h-3 w-3' />
          <span className='truncate'>{event.location.split(',')[0]}</span>
        </div>

        <div className='mt-auto flex items-center justify-between border-t border-gray-100 pt-3'>
          <div>
            <span className='block text-xs text-gray-500'>Starting from</span>
            <span className='text-sm font-bold text-gray-900'>
              {event.price === 0 ? 'FREE' : formatRupiah(event.price)}
            </span>
          </div>
          <div className='flex items-center text-xs text-gray-500'>
            <Star className='mr-1 h-3 w-3 fill-current text-yellow-400' />
            {event.interestedCount} interested
          </div>
        </div>
      </div>
    </div>
  );
};

export const StatusBadge: React.FC<{ status: TransactionStatus }> = ({
  status,
}) => {
  const colors = {
    [TransactionStatus.WAITING_PAYMENT]: 'bg-yellow-100 text-yellow-800',
    [TransactionStatus.WAITING_CONFIRMATION]: 'bg-blue-100 text-blue-800',
    [TransactionStatus.DONE]: 'bg-green-100 text-green-800',
    [TransactionStatus.REJECTED]: 'bg-red-100 text-red-800',
    [TransactionStatus.EXPIRED]: 'bg-gray-100 text-gray-800',
    [TransactionStatus.CANCELLED]: 'bg-red-100 text-red-800',
  };

  const labels = {
    [TransactionStatus.WAITING_PAYMENT]: 'Menunggu Pembayaran',
    [TransactionStatus.WAITING_CONFIRMATION]: 'Verifikasi Admin',
    [TransactionStatus.DONE]: 'Selesai',
    [TransactionStatus.REJECTED]: 'Ditolak',
    [TransactionStatus.EXPIRED]: 'Kedaluwarsa',
    [TransactionStatus.CANCELLED]: 'Dibatalkan',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${colors[status]}`}
    >
      {labels[status]}
    </span>
  );
};
