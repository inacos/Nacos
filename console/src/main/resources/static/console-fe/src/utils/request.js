import axios from 'axios';
import { Message } from '@alifd/next';
// import { SUCCESS_RESULT_CODE } from '../constants';

const API_GENERAL_ERROR_MESSAGE = 'Request error, please try again later!';

const request = () => {
  const instance = axios.create();
  // add Authorization for console interface
  instance.interceptors.request.use(config => {
    config.headers.Authorization = localStorage.getItem('token');
    return config;
  });

  instance.interceptors.response.use(
    response => {
      const { success, resultCode, resultMessage = API_GENERAL_ERROR_MESSAGE } = response.data;
      // if (!success && resultCode !== SUCCESS_RESULT_CODE) {
      //   Message.error(resultMessage);
      //   return Promise.reject(new Error(resultMessage));
      // }
      return response.data;
    },
    error => {
      if (error.response) {
        const { status } = error.response;
        Message.error(`HTTP ERROR: ${status}`);
      } else {
        Message.error(API_GENERAL_ERROR_MESSAGE);
      }
      return Promise.reject(error);
    }
  );

  return instance;
};

export default request();
