import { renderHook, act } from '@testing-library/react-hooks';
import useDebounce from '../hooks/useDebounce';

jest.useFakeTimers();

test('useDebounce returns debounced value after delay', () => {
  const { result, rerender } = renderHook(
    ({ val, delay }) => useDebounce(val, delay),
    {
      initialProps: { val: 'a', delay: 300 },
    }
  );

  expect(result.current).toBe('a');

  rerender({ val: 'ab', delay: 300 });
  act(() => {
    jest.advanceTimersByTime(299);
  });
  expect(result.current).toBe('a');

  act(() => {
    jest.advanceTimersByTime(1);
  });
  expect(result.current).toBe('ab');
});
