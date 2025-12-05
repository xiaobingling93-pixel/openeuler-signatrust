<template>
  <el-form
    label-position="right"
    label-width="auto"
    :model="formLabelAlign"
    :rules="rules"
    ref="ruleFormRef"
  >
    <div class="table">
      <el-form-item label="Name" prop="name">
        <el-input
          v-model="formLabelAlign.name"
          placeholder="Name should be identical, ‘:’ character is not allowed"
        />
      </el-form-item>
      <el-form-item label="Description" prop="description">
        <el-input
          v-model="formLabelAlign.description"
          placeholder="Description of this key"
        />
      </el-form-item>
      <el-form-item label="Private key" prop="private_key">
        <el-input
          v-model="formLabelAlign.private_key"
          type="textarea"
          placeholder="private key content in pem format"
        />
      </el-form-item>
      <el-form-item label="Public key" prop="public_key">
        <el-input
          v-model="formLabelAlign.public_key"
          type="textarea"
          placeholder="public key content in pem format"
        />
      </el-form-item>
      <el-form-item label="Certificate" prop="certificate">
        <el-input
          v-model="formLabelAlign.certificate"
          type="textarea"
          placeholder="certificate content in pem format"
        />
      </el-form-item>
      
      <el-form-item label="Visibility">
        <el-radio-group
          v-model="formLabelAlign.visibility"
          class="ml-4"
          @chaneg="getChange()"
        >
          <el-radio label="private" title="The private key pairs are managed by yourself, no one else can seen/use your private key pairs.">Private</el-radio>
          <el-radio label="public" title="The public key pairs can be created/used by any administrator, but in order to delete it, it require triple confirms from different administrators.">Public</el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item label="Expire" prop="expire_at">
        <el-date-picker
          v-model="formLabelAlign.expire_at"
          type="date"
          placeholder="Choose expire date time"
          :disabled-date="pickerOptions"
        />
      </el-form-item>
      <div class="sel">
        <el-form-item label="Digest Algorithm">
          <el-select v-model="formLabelAlign.digest_algorithm" class="m-2" size="small">
            <el-option
              v-for="item in optionsDigest"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>
      </div>
      <el-form-item label="Type">
        <el-input placeholder="X509" disabled />
      </el-form-item>
    </div>
    <div class="dialog-footer">
      <el-button @click="resetForm(ruleFormRef)">Cancel</el-button>
      <el-button type="primary" @click="submitForm(ruleFormRef)"> Confirm </el-button>
    </div>
  </el-form>
  <el-dialog v-model="dialogVisible" title="Warning" width="20%" :show-close="true" align-center>
    {{ worryDetail }}
  </el-dialog>
</template>
<script setup lang="ts">
import { reactive, ref, watch, computed } from "vue";
import { useBaseStore } from "@/store/base";
import { queryImportKey, headName } from "@/api/show";
import type { FormInstance, FormRules } from "element-plus";
import { useDataStore } from "@/store/data";
import { originalDate } from "@/shared/utils/helper";
const useData = useDataStore();
const ruleFormRef = ref<FormInstance>();
const useBase = useBaseStore();
const dialogVisible = ref(false);
const formLabelAlign = reactive<any>({
  name: "",
  description: "",
  visibility: "private",
  private_key: "",
  public_key: "",
  certificate: "",
  key_type: "x509ee",
  keytype: "rsa",
  key_length: "2048",
  digest_algorithm: "md5",
});
const param = ref({
  attributes: {
    key_type: "rsa",
    key_length: "2048",
    digest_algorithm: "sha1",
    passphrase: "password",
    expire_at: "",
  },
  certificate: "",
  description: "",
  key_type: "string",
  name: "string",
  private_key: "string",
  public_key: "string",
  visibility: "string",
});
const optionsType = [
  {
    value: "rsa",
    label: "RSA",
  },
  {
    value: "dsa",
    label: "DSA",
  },
  {
    value: "sm2",
    label: "SM2",
  }
];
const optionsSize = [
  {
    value: '256',
    label: '256',
  },
  {
    value: "2048",
    label: "2048",
  },
  {
    value: "3072",
    label: "3072",
  },
  {
    value: "4096",
    label: "4096",
  },
];
const optionsDigest = [
  {
    value: "md5",
    label: "md5",
  },
  {
    value: "sha1",
    label: "sha1",
  },
  {
    value: "sha2_224",
    label: "sha2_224",
  },
  {
    value: "sha2_256",
    label: "sha2_256",
  },
  {
    value: "sha2_384",
    label: "sha2_384",
  },
  {
    value: "sha2_512",
    label: "sha2_512",
  },
  {
    value: "sm3",
    label: "sm3",
  },
];
// 表单校验规则
/* 姓名 */
const isName = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback();
  } else {
    const reg = /^[a-zA-Z0-9-]{4,256}$/;
    const name = reg.test(value);
    if (!name) {
      callback(new Error("The value contains 4 to 256 English characters"));
    } else {
      const param = ref({
        name: value,
        visibility: computed(() => formLabelAlign.visibility),
      });
      headName(param.value)
        .then(() => callback())
        .catch(() => callback(new Error("Duplicate name")));
    }
  }
};
/* 描述 */
const isDesc = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback();
  } else {
    const reg = /^[a-zA-Z0-9-]{1,200}$/;
    const desc = reg.test(value);
    if (!desc) {
      callback(new Error("The value contains a maximum of 100 English characters"));
    } else {
      callback();
    }
  }
};
const rules = reactive<FormRules>({
  name: [
    { required: true, message: "please enter" },
    { validator: isName, trigger: ["change"] },
  ],
  description: [
    { required: true, message: "Please enter a description", trigger: "blur" },
    { validator: isDesc, trigger: ["blur", "change"] },
  ],
  private_key: [
    { required: true, message: "Please enter private key", trigger: ["blur", "change"] },
  ],
  certificate: [
    { required: true, message: "Please enter certificate", trigger: ["blur", "change"] },
  ],
  expire_at: [
    { required: true, message: "Please enter expire", trigger: ["blur", "change"] },
  ],
});
//表单请求
const worryDetail = ref();
const importKey = () => {
  queryImportKey(param.value)
    .then((res) => {
      useBase.dialogVisible = false;
      useData.getTableData();
      useData.getPriTableData();
      formLabelAlign.expire_at = "";
      formLabelAlign.visibility = "private";
      formLabelAlign.certificate = "";
    })
    .catch((res) => {
      worryDetail.value = res.response.data.detail;
      dialogVisible.value = true;
    });
};
//获取表单值
const getData = () => {
  param.value.name = formLabelAlign.name;
  param.value.visibility = formLabelAlign.visibility;
  param.value.public_key = formLabelAlign.public_key;
  param.value.key_type = formLabelAlign.key_type;
  param.value.private_key = formLabelAlign.private_key;
  param.value.certificate = formLabelAlign.certificate;
  param.value.attributes.key_length = formLabelAlign.key_length;
  param.value.attributes.key_type = formLabelAlign.keytype;
  param.value.attributes.digest_algorithm = formLabelAlign.digest_algorithm;
  param.value.attributes.expire_at = originalDate(formLabelAlign.expire_at);
  param.value.description = formLabelAlign.description;
};
//提交表单
const submitForm = async (formEl: FormInstance | undefined) => {
  if (!formEl) return;
  await formEl.validate((valid, fields) => {
    if (valid) {
      getData();
      importKey();
    } else {
      return false;
    }
  });
};
//关闭表单
const resetForm = (formEl: FormInstance | undefined) => {
  if (!formEl) return;
  useBase.dialogVisible = false;
  formEl.resetFields();
  formLabelAlign.expire_at = "";
  formLabelAlign.visibility = "private";
  formLabelAlign.certificate = "";
};

const pickerOptions = (time: any) => {
  return time?.getTime() <= new Date().getTime();
};
//改变radio
const getChange = () => {
  formLabelAlign.name = "";
};
</script>
<style scoped lang="scss">
.table {
  padding: 24px;
  .sel {
    display: flex;
    .m-2 {
      padding-right: 24px;
    }
  }
}
.dialog-footer button:first-child {
  margin-right: 10px;
}
.dialog-footer {
  margin-top: 30px;
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
<style lang="scss">
// .sel {
//   .el-select .el-input__inner {
//     width: 80px;
//     height: 24px;
//     margin-right: 2px;
//     margin-left: 2px;
//   }
// }
// .el-input__wrapper {
//   padding: 0px 11px;
//   border-radius: none !important;
// }
</style>
