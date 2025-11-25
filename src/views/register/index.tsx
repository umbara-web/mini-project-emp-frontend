'use client';

import { Formik, Form, FormikProps } from 'formik';
import { useSnackbar } from 'notistack';
import RegisterSchema from './schema';
import { useRouter } from 'next/router';

interface IRegister {
  name: string;
  email: string;
  password: string;
}

export default function RegView() {
  const initVal = { name: '', email: '', password: '' };
  const { enqueueSnackbar } = useSnackbar();
  const router = useRouter();
  return (
    <div>
      <h1>Register page</h1>
      <Form>
        <div>
          <label htmlFor=''>Name</label>
          <input type='text' name='name' />
        </div>

        <div>
          <label htmlFor=''>Email</label>
          <input type='text' name='email' />
        </div>

        <div>
          <label htmlFor=''>Password</label>
          <input type='password' name='password' />
        </div>
        
        <div>
          <button type='submit'>Register</button>
        </div>
      </Form>
    </div>
  );
}
