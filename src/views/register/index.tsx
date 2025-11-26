'use client';

import { Formik, Form, FormikProps } from 'formik';

import { useSnackbar } from 'notistack';
import RegisterSchema from './schema';
import { useRouter } from 'next/router';
import { IRegister } from '@/src/interfaces/register.interface';
import { verificationLinkService } from '@/src/services/auth';

export default function RegView() {
  const initVal = { name: '', email: '', password: '', role: '' };
  const { enqueueSnackbar } = useSnackbar();
  const router = useRouter();

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
    <Formik<IRegister>
      initialValues={initVal}
      validationSchema={RegisterSchema}
      onSubmit={handleSubmit}
    >
      {(props: FormikProps<IRegister>) => (
        <Form className=''>
          <div className=''>
            <label>Email:</label>
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
            <label htmlFor="">Password:</label>
            <input type="password"
            name='password'
            value={props.values.password} 
            onChange={props.handleChange}/>
          </div>
          <div>
            
          </div>
          
          <button type='submit'>Register</button>
        </Form>
      )}
    </Formik>
  );
}
