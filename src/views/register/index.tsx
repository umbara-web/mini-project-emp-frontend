'use client';

import { Formik, Form, FormikProps } from 'formik';
import { useSnackbar } from 'notistack';
import RegisterSchema from './schema';
import { IRegister } from '@/src/interfaces/register.interface';
import { verificationLinkService } from '@/src/services/auth';

export default function RegView() {
  const initVal = { name: '', email: '', password: '', role: '' };
  const { enqueueSnackbar } = useSnackbar();
  const roles = [
    { value: 'customer', label: 'Customer' },
    { value: 'eventOrganizer', label: 'Event Organizer' },
  ];

  async function handleSubmit(values: IRegister) {
    try {
      const data = await verificationLinkService(values.email);

      enqueueSnackbar(data.message, { variant: 'success' });
    } catch (err) {
      if (err instanceof Error) {
        enqueueSnackbar(err.message, { variant: 'error' });
      } else {
        enqueueSnackbar('Something went wrong', { variant: 'error' });
      }
    }
  }

  return (
    <div className='flex min-h-screen items-center justify-center'>
      <div className='relative mx-4 w-full max-w-md'>
        <Formik<IRegister>
          initialValues={initVal}
          validationSchema={RegisterSchema}
          onSubmit={handleSubmit}
        >
          {(props: FormikProps<IRegister>) => (
            <Form className='flex flex-col gap-3'>
              <div className='flex flex-col gap-3'>
                <label htmlFor=''>Name:</label>
                <input
                  className='rounded-md border p-2'
                  type='text'
                  name='name'
                  value={props.values.name}
                  onChange={props.handleChange}
                />
              </div>

              <div className='flex flex-col gap-3'>
                <label htmlFor='' className=''>
                  Email:
                </label>
                <input
                  className='rounded-md border p-2'
                  type='email'
                  name='email'
                  value={props.values.email}
                  onChange={props.handleChange}
                />
                {props.touched.email && props.errors.email && (
                  <span>*{props.errors.email}</span>
                )}
              </div>

              <div>
                <label htmlFor=''>Password:</label>
                <input
                  className='rounded-md border p-2'
                  type='password'
                  name='password'
                  value={props.values.password}
                  onChange={props.handleChange}
                />
              </div>

              <div className='flex flex-col gap-2'>
                <label htmlFor='role'>Register as:</label>

                <select
                  name='role'
                  value={props.values.role}
                  onChange={props.handleChange}
                  className='cursor-pointer appearance-none rounded-md border p-2'
                >
                  <option value='customer'>Customer</option>
                  <option value='eventOrganizer'>Event Organizer</option>
                </select>
              </div>

              <button type='submit'>Register</button>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
}
