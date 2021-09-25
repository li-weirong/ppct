import os
import sys
import numpy as np
import opendp.smartnoise.core as sn
data_path = os.path.join('.', 'data', 'PUMS.csv')
var_names = ["age", "sex", "educ", "race", "income", "married", "pid"]
with sn.Analysis() as analysis: #使用分析来描述计算
    data = sn.Dataset(path = data_path, column_names = var_names)
    age_dt = sn.to_float(data['age'])
    age_dt = sn.clamp(age_dt, lower = 0., upper = 100.)
    age_dt = sn.impute(data = age_dt, 
                       distribution = 'Gaussian',
                       lower = 0., upper = 100.,
                       shift = 45., scale = 10.)
    age_dt = sn.resize(data = age_dt, number_rows = 1000, 
                       distribution = 'Gaussian',
                       lower = 0., upper = 100.,
                       shift = 45., scale = 10.)
    # 计算满足差分隐私的年龄平均值
    age_mean = sn.dp_mean(data = age_dt, privacy_usage={'epsilon': .65})
    # 计算满足差分隐私的年龄的方差
    age_var = sn.dp_variance(data = age_dt, privacy_usage={'epsilon': .35})
analysis.release()
print(age_mean.value)
print(age_var.value)

with sn.Analysis() as analysis: #使用分析来描述计算
    data = sn.Dataset(path = data_path, column_names = var_names)
    age_dt = sn.to_float(data['age'])
    age_mean = sn.dp_mean(data = age_dt,
                          privacy_usage = {'epsilon': .65},
                          mechanism = 'Snapping',
                          data_lower = 0.,
                          data_upper = 100.,
                          data_rows = 1000
                         )
analysis.release()
print(age_mean.value)
