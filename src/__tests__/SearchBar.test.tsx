import { render, screen, fireEvent } from '@testing-library/react';
import SearchBar from '../components/SearchBar';

test('SearchBar updates input and clears', () => {
  const handle = jest.fn();
  render(<SearchBar onSearch={handle} />);
  const input = screen.getByPlaceholderText(/Cari acara/i);
  fireEvent.change(input, { target: { value: 'konser' } });
  expect((input as HTMLInputElement).value).toBe('konser');
  const clearBtn = screen.getByText(/Clear/i);
  fireEvent.click(clearBtn);
  expect((input as HTMLInputElement).value).toBe('');
});
