import axios from 'axios';
const BASE = '/api';

// 请求拦截器：自动注入 Authorization header，无需每个接口手动传入
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截器：统一处理 401（token 过期或无效时清除并通知应用回到登录页）
axios.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token');
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) => axios.post(`${BASE}/login`, { username, password });

// 获取当前登录用户的上次登录时间 / IP
export const getMe = () => axios.get(`${BASE}/users/me`);

// 菜单相关API
export const getMenus = () => axios.get(`${BASE}/menus`);
export const addMenu = (data) => axios.post(`${BASE}/menus`, data);
export const updateMenu = (id, data) => axios.put(`${BASE}/menus/${id}`, data);
export const deleteMenu = (id) => axios.delete(`${BASE}/menus/${id}`);

// 子菜单相关API
export const getSubMenus = (menuId) => axios.get(`${BASE}/menus/${menuId}/submenus`);
export const addSubMenu = (menuId, data) => axios.post(`${BASE}/menus/${menuId}/submenus`, data);
export const updateSubMenu = (id, data) => axios.put(`${BASE}/menus/submenus/${id}`, data);
export const deleteSubMenu = (id) => axios.delete(`${BASE}/menus/submenus/${id}`);

// 卡片相关API
export const getCards = (menuId, subMenuId = null) => {
  const params = subMenuId ? { subMenuId } : {};
  return axios.get(`${BASE}/cards/${menuId}`, { params });
};
export const addCard = (data) => axios.post(`${BASE}/cards`, data);
export const updateCard = (id, data) => axios.put(`${BASE}/cards/${id}`, data);
export const deleteCard = (id) => axios.delete(`${BASE}/cards/${id}`);

// 全局搜索卡片
export const searchCards = (q) => axios.get(`${BASE}/cards/search`, { params: { q } });

export const uploadLogo = (file) => {
  const formData = new FormData();
  formData.append('logo', file);
  return axios.post(`${BASE}/upload`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
};

// 广告API
export const getAds = () => axios.get(`${BASE}/ads`);
export const addAd = (data) => axios.post(`${BASE}/ads`, data);
export const updateAd = (id, data) => axios.put(`${BASE}/ads/${id}`, data);
export const deleteAd = (id) => axios.delete(`${BASE}/ads/${id}`);

// 友链API
export const getFriends = () => axios.get(`${BASE}/friends`);
export const addFriend = (data) => axios.post(`${BASE}/friends`, data);
export const updateFriend = (id, data) => axios.put(`${BASE}/friends/${id}`, data);
export const deleteFriend = (id) => axios.delete(`${BASE}/friends/${id}`);

// 用户API
export const getUserProfile = () => axios.get(`${BASE}/users/profile`);
export const changePassword = (oldPassword, newPassword) => axios.put(`${BASE}/users/password`, { oldPassword, newPassword });
export const getUsers = () => axios.get(`${BASE}/users`);

// 数据备份 / 迁移
export const exportBackup = () => axios.get(`${BASE}/backup/export`);
export const importBackup = (payload) => axios.post(`${BASE}/backup/import`, payload);
