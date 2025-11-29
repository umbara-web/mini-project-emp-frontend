'use client';

import { Formik, Form, FormikProps } from 'formik';
import { useSnackbar } from 'notistack';
import { ILogin } from '@/src/interfaces/login.interface';
import LoginSchema from './schema';
import { login } from '@/src/services/auth';
import { loginService } from '@/src/stores/authStore';



export default function LoginView() {
  const initVal = { email: '', password: '' };
  const { enqueueSnackbar } = useSnackbar();
  return (
    <div>
      <h1>Login page</h1>
      <Formik<ILogin>
        initialValues={initVal}
        onSubmit={async (values) => {
          try {
            //


          } catch (error) {
            if (error instanceof Error) {
              enqueueSnackbar(error.message, { variant: 'error' });
            } else {
              console.log(error);
              enqueueSnackbar('Something went wrong', { variant: 'error' });
            }
          }
        }}
      >
        {(props: FormikProps<ILogin>) => (
          <Form>
            <div>
              <label htmlFor=''>Email</label>
              <input
                type='text'
                name='email'
                value={props.values.email}
                onChange={props.handleChange}
              />
            </div>

            <div>
              <label htmlFor=''>Password</label>
              <input
                type='password'
                name='password'
                value={props.values.password}
                onChange={props.handleChange}
              />
            </div>
            {props.touched.password && props.errors.password && (
              <span>*{props.errors.password}</span>
            )}
            <div>
              <button type='submit'>Login</button>
            </div>
          </Form>
        )}
      </Formik>
    </div>
  );
}
