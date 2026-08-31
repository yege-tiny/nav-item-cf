<template>
  <nav class="menu-bar">
    <div 
      v-for="menu in menus" 
      :key="menu.id" 
      class="menu-item"
      @mouseenter="showSubMenu(menu.id)"
      @mouseleave="hideSubMenu(menu.id)"
    >
      <button 
        @click="$emit('select', menu)" 
        :class="{active: menu.id === activeId}"
      >
        {{ menu.name }}
      </button>
      
      <!-- 二级菜单 -->
      <div 
        v-if="menu.subMenus && menu.subMenus.length > 0" 
        class="sub-menu"
        :class="{ 'show': hoveredMenuId === menu.id }"
      >
        <button 
          v-for="subMenu in menu.subMenus" 
          :key="subMenu.id"
          @click="$emit('select', subMenu, menu)"
          :class="{active: subMenu.id === activeSubMenuId}"
          class="sub-menu-item"
        >
          {{ subMenu.name }}
        </button>
      </div>
    </div>
  </nav>
</template>

<script setup>
import { ref } from 'vue';

const props = defineProps({ 
  menus: Array, 
  activeId: Number,
  activeSubMenuId: Number 
});

const hoveredMenuId = ref(null);

function showSubMenu(menuId) {
  hoveredMenuId.value = menuId;
}

function hideSubMenu(menuId) {
  // 延迟隐藏，给用户时间移动到子菜单
  setTimeout(() => {
    if (hoveredMenuId.value === menuId) {
      hoveredMenuId.value = null;
    }
  }, 100);
}
</script>

<style scoped>
.menu-bar {
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  padding: 0 1rem;
  position: relative;
}

.menu-item {
  position: relative;
}

/* NOTE: 主菜单按钮使用 .menu-item > button 限定范围，避免污染子菜单 */
.menu-item > button {
  background: transparent;
  border: none;
  color: #fff;
  font-size: 16px;
  font-weight: 500;
  padding: 0.8rem 2rem;
  cursor: pointer;
  transition: all 0.3s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
  box-shadow: none;
  border-radius: 8px;
  position: relative;
  overflow: hidden;
}

.menu-item > button::before {
  content: '';
  position: absolute;
  bottom: 0;
  left: 50%;
  width: 0;
  height: 2px;
  background: #399dff;
  transition: all 0.3s ease;
  transform: translateX(-50%);
}

.menu-item > button:hover {
  color: #399dff;
  transform: translateY(-1px);
}

.menu-item > button.active {
  color: #399dff;
}

.menu-item > button.active::before {
  width: 60%;
}

/* 二级菜单容器 */
.sub-menu {
  position: absolute;
  top: 100%;
  left: 50%;
  transform: translateX(-50%);
  background: #5c595900;
  backdrop-filter: blur(8px);
  border-radius: 6px;
  min-width: 120px;
  opacity: 0;
  visibility: hidden;
  transition: all 0.2s ease;
  z-index: 1000;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(255, 255, 255, 0.15);
  margin-top: -2px; 
}

.sub-menu.show {
  opacity: 1;
  visibility: visible;
  transform: translateX(-50%) translateY(2px);
}

/* NOTE: 子菜单按钮使用 .sub-menu > .sub-menu-item 选择器，
   优先级高于 .menu-item > button，无需 !important */
.sub-menu > .sub-menu-item {
  display: block;
  width: 100%;
  text-align: center;
  padding: 0.4rem 1rem;
  border: none;
  background: transparent;
  color: #fff;
  font-size: 14px;
  font-weight: 400;
  cursor: pointer;
  transition: all 0.2s ease;
  border-radius: 0;
  text-shadow: none;
  line-height: 1.5;
  box-shadow: none;
  overflow: visible;
  position: relative;
}

.sub-menu > .sub-menu-item::before {
  display: none;
}

.sub-menu > .sub-menu-item:hover {
  background: rgba(57, 157, 255, 0.25);
  color: #399dff;
  transform: none;
}

.sub-menu > .sub-menu-item.active {
  background: rgba(57, 157, 255, 0.35);
  color: #399dff;
  font-weight: 500;
}

@media (max-width: 768px) {
  .menu-bar {
    gap: 0.2rem;
  }
  
  .menu-item > button {
    font-size: 14px;
    padding: .4rem .8rem;
  }
  
  .sub-menu {
    min-width: 100px;
  }
  
  .sub-menu > .sub-menu-item {
    font-size: 8px;
    padding: 0.2rem 0.8rem;
  }
}
</style> 