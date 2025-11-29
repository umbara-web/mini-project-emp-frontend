'use client';

import { Formik, Form, FormikProps } from 'formik';
import { useSnackbar } from 'notistack';
import RegisterSchema from './schema';
import { IRegister } from '@/src/interfaces/register.interface';
import { verificationLinkService } from '@/src/services/auth';

import { DropdownMenu,DropdownMenuItem,DropdownMenuContent,DropdownMenuTrigger, DropdownMenuSeparator,DropdownMenuLabel } from '@radix-ui/react-dropdown-menu';

export default function RegView() {
  const initVal = { name: '', email: '', password: '', role: '' };
  const { enqueueSnackbar } = useSnackbar();
 

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
    <div>
      <h1>Register</h1>
      <Formik<IRegister>
      initialValues={initVal}
      validationSchema={RegisterSchema}
      onSubmit={handleSubmit}
    >
      {(props: FormikProps<IRegister>) => (
        <Form className=''>
          <div className=''>
            <label htmlFor=''>Email:</label>
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
            <input 
            className='rounded-md border p-2'
            type="password"
            name='password'
            value={props.values.password} 
            onChange={props.handleChange}/>
          </div>
          <div>
            <DropdownMenu>
              <DropdownMenuTrigger>Role</DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem>Costumer</DropdownMenuItem>
                <DropdownMenuItem>Event Organizer</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          
          <button type='submit'>Register</button>
        </Form>
      )}
    </Formik>
    </div>
    
  );
}
