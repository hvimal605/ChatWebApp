import React, { useEffect } from 'react';
import { useForm } from "react-hook-form";
import { Link } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthProvider';
import toast from 'react-hot-toast';

const Login = () => {
    const [authUser, setAuthUser] = useAuth();
    
    const {
        register,
        handleSubmit,
        reset,
        formState: { errors, isSubmitSuccessful },
    } = useForm();

    const submitLoginForm = (data) => {
        const userinfo = {
            email: data.email,
            password: data.password,
        };
       
        axios.post("http://localhost:3000/api/user/login", userinfo, {
            withCredentials: true // Allows sending and receiving cookies
        })
        .then((response) => {
            if (response.data) {
                toast.success("Login Successful");
            }
            localStorage.setItem("Chatapp", JSON.stringify(response.data));
            setAuthUser(response.data);
        })
        .catch((error) => {
            if (error.response) {
                toast.error("Error: " + error.response.data.error);
            }
        });
    };
   
    useEffect(() => {
        if (isSubmitSuccessful) {
            reset({
                email: "",
                password: "",
            });
        }
    }, [reset, isSubmitSuccessful]);

    return (
        <div className='flex justify-center items-center h-screen p-4'>
            <div className='w-full max-w-md bg-white shadow-lg rounded-xl p-6'>
                <div className='text-center text-2xl font-semibold mb-6'>Login</div>
                
                <form
                    onSubmit={handleSubmit(submitLoginForm)}
                    className='flex flex-col space-y-4'
                >
                    <label className='font-semibold' htmlFor='email'>
                        Email <sup className='text-red-600'>*</sup>
                    </label>
                    <input
                        type="email"
                        id="email"
                        className='border-2 border-blue-700 p-2 rounded-md shadow-md w-full'
                        {...register("email", { required: true })}
                    />
                    {errors.email && (
                        <span className="text-red-500 text-sm">
                            Please enter your email.
                        </span>
                    )}

                    <label className='font-semibold' htmlFor='password'>
                        Password <sup className='text-red-600'>*</sup>
                    </label>
                    <input
                        type="password"
                        id="password"
                        className='border-2 border-blue-700 p-2 rounded-md shadow-md w-full'
                        {...register("password", { required: true })}
                    />
                    {errors.password && (
                        <span className="text-red-500 text-sm">
                            Please enter your Password.
                        </span>
                    )}

                    <div className='text-blue-500 text-sm'>
                        <Link to='/ResetPassword'>Forgot Password?</Link>
                    </div>

                    <button
                        type="submit"
                        className='bg-yellow-400 hover:bg-yellow-500 p-2 rounded-md  w-full'
                    >
                        Login
                    </button>
                </form>

                <div className='text-black text-center my-4'>
                    <span>------</span> OR <span>------</span>
                </div>
                
                <Link to='/signup'>
                    <div className='text-blue-500 text-center hover:bg-sky-100 hover:cursor-pointer p-2 rounded-md transition-all duration-300'>
                        Signup
                    </div>
                </Link>
            </div>
        </div>
    );
}

export default Login;
