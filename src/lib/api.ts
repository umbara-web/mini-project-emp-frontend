type Event = {
  id: string;
  title: string;
  date: string;
  location: string;
  price: number;
  seats: number;
  description?: string;
  organizerId?: string;
};

const MOCK_EVENTS: Event[] = [
  {
    id: 'evt-1',
    title: 'Konser Amal: Musik Untuk Semua',
    date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString(),
    location: 'Jakarta Convention Center',
    price: 150000,
    seats: 200,
    description: 'Konser amal dengan berbagai penampil lokal.',
    organizerId: 'org-1',
  },
  {
    id: 'evt-2',
    title: 'Workshop UI/UX Intensif',
    date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString(),
    location: 'Bandung',
    price: 0,
    seats: 50,
    description: 'Pelajari dasar-dasar UI/UX dalam 2 hari intensif.',
    organizerId: 'org-2',
  },
  {
    id: 'evt-3',
    title: 'Pameran Startup Lokal',
    date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
    location: 'Surabaya',
    price: 50000,
    seats: 300,
    description: 'Pameran dan networking untuk startup lokal.',
    organizerId: 'org-1',
  },
];

export async function fetchEvents(): Promise<Event[]> {
  // simulate network delay
  await new Promise((r) => setTimeout(r, 250));
  return MOCK_EVENTS;
}

export async function getEventById(id: string): Promise<Event | null> {
  await new Promise((r) => setTimeout(r, 150));
  return MOCK_EVENTS.find((e) => e.id === id) ?? null;
}

export async function createEvent(payload: Partial<Event>): Promise<Event> {
  const ev: Event = {
    id: `evt-${Date.now()}`,
    title: payload.title || 'Untitled',
    date: payload.date || new Date().toISOString(),
    location: payload.location || '',
    price: payload.price ?? 0,
    seats: payload.seats ?? 0,
    description: payload.description || '',
    organizerId: payload.organizerId || 'org-unknown',
  };
  MOCK_EVENTS.push(ev);
  return ev;
}
