<template>
  <div class="container">
    <div v-for="(item, index) in check" :key="item" @click="showDetail(item)">
      {{ item }}
    </div>
    <el-dialog
      v-model="useBase.dialogVisible"
      :title="title"
      width="70%"
      :show-close="false"
      center
      :before-close="close"
    >
      <CreatePgp v-if="title === 'Create PGP Keys'"/>
      <CreateX509 v-if="title === 'Create X509 Keys'" />
      <ImportPgp v-if="title === 'Import PGP Keys'" />
      <ImportX509 v-if="title === 'Import X509 Keys'" />
    </el-dialog>
  </div>
</template>
<script setup lang="ts">
import { ref,reactive } from "vue";
import CreatePgp from "./CreatePgp.vue";
import CreateX509 from "./CreateX509.vue";
import ImportPgp from "./ImportPgp.vue";
import ImportX509 from "./ImportX509.vue";
import { useBaseStore } from "@/store/base";
const useBase = useBaseStore();
const title = ref();
const check = [
  "Import X509 Keys",
  // "Import PGP Keys",
  "Create X509 Keys",
  "Create PGP Keys",
];
const showDetail = (item: any) => {
  useBase.dialogVisible = true;
  title.value = item;
};
const close = ()=>{}



</script>
<style scoped lang="scss">
.container {
  overflow: hidden;
  margin-bottom: 24px;
}

.container div {
  height: 32px;
  padding: 5px 13px;
  border: 1px solid #00195a;
  margin-left: 10px;
  font-size: 14px;
  color: #00195a;
  float: right;
  cursor: pointer;
}
</style>
<style scoped>
.dialog-footer button:first-child {
  margin-right: 10px;
}
.el-dialog--center .el-dialog__body {
  display: flex;
  justify-content: center;
}
</style>
