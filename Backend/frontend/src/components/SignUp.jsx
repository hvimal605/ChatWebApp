import React, { useEffect } from 'react';
import { useForm } from "react-hook-form";
import { Link } from 'react-router-dom';
import axios from "axios";
import { useAuth } from '../context/AuthProvider';
import toast from 'react-hot-toast';

const SignUp = () => {
    const [authUser, setAuthUser] = useAuth();
    const {
        register,
        handleSubmit,
        reset,
        watch,
        formState: { errors, isSubmitSuccessful },
    } = useForm();

    // Watch the password and confirm password field
    const password = watch("password", "");
    const confirmpassword = watch("confirmpassword", "");

    const validatePasswordMatch = (value) => {
        return value === password || "Password do not match";
    };

    const submitSignupForm = async (data) => {
        const userinfo = {
            fullname: data.name,
            email: data.email,
            password: data.password,
            confirmPassword: data.confirmpassword
        };

        await axios.post("http://localhost:3000/api/user/signup", userinfo)
            .then((response) => {
                if (response.data) {
                    toast.success("Signup successful");
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
                name: "",
                email: "",
                password: "",
                confirmpassword: ""
            });
        }
    }, [reset, isSubmitSuccessful]);

    return (
        <div className='flex justify-center items-center h-screen p-4'>
            <div className='w-full max-w-md bg-white shadow-lg rounded-xl p-6'>
                <div>
                    <div className='text-center text-2xl md:text-3xl font-semibold mb-6'>SignUp</div>
                    
                    <form
                        onSubmit={handleSubmit(submitSignupForm)}
                        className='flex flex-col space-y-4'
                    >
                        <label className='font-semibold' htmlFor='name'>
                            Name <sup className='text-red-600'>*</sup>
                        </label>
                        <input
                            type="text"
                            id="name"
                            className='border-2 border-blue-700 p-2 rounded-md shadow-md w-full'
                            {...register("name", { required: true })}
                        />
                        {errors.name && (
                            <span className="text-red-500 text-sm">
                                Please enter your name.
                            </span>
                        )}

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
                                Please enter your password.
                            </span>
                        )}

                        <label className='font-semibold' htmlFor='confirmpassword'>
                            Confirm Password <sup className='text-red-600'>*</sup>
                        </label>
                        <input
                            type="password"
                            id="confirmpassword"
                            className='border-2 border-blue-700 p-2 rounded-md shadow-md w-full'
                            {...register("confirmpassword", { required: true, validate: validatePasswordMatch })}
                        />
                        {errors.confirmpassword && (
                            <span className="text-red-500 text-sm">
                                {errors.confirmpassword.message}
                            </span>
                        )}

                        <button
                            type="submit"
                            className='bg-yellow-400 hover:bg-yellow-500 p-2 rounded-md text-black w-full   transition-transform duration-300'
                        >
                            SignUp
                        </button>
                    </form>

                    <div className='text-black text-center my-4'>
                        <span>------</span> OR <span>------</span>
                    </div>
                    
                    <Link to='/login'>
                        <div className='text-blue-500 text-center hover:bg-sky-100 hover:cursor-pointer p-2 rounded-md transition-all duration-300'>
                            Login
                        </div>
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default SignUp;
