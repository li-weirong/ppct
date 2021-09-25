import os
import opendp.smartnoise.core as sn
data_path = os.path.join('.', 'data', 'PUMS.csv')
var_names = ["age", "sex", "educ", "race", "income", "married"] #字段名称
income_edges = list(range(0, 100000, 10000)) #收入分成10段
education_categories = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", 
                        "11", "12", "13", "14", "15", "16"]
with sn.Analysis() as analysis:
    data = sn.Dataset(path = data_path, column_names = var_names)
    nsize = 1000
    #使用核心库支持的差分隐私直方图统计工具
    income_histogram = sn.dp_histogram(
            sn.to_int(data['income'], lower=0, upper=100), #强制转化成整形
            edges = income_edges, #数据分箱
            upper = nsize, #分箱后单一箱体内的最大数据量
            mechanism = 'SimpleGeometric', #采用简单几何机制
            privacy_usage = {'epsilon': 0.5}
        )
    sex_histogram = sn.dp_histogram( #dp_histogram默认使用简单几何机制
            sn.to_bool(data['sex'], true_label="0"), #强制转化成布尔形
            upper = nsize,
            privacy_usage = {'epsilon': 0.5}
        )
    education_histogram = sn.dp_histogram( #dp_histogram默认使用简单几何机制
            data['educ'],
            categories = education_categories,
            null_value = "-1", #如果数据不再categories范围则设为-1
            privacy_usage = {'epsilon': 0.5}
        )
analysis.release()
print("Income histogram Geometric DP release:   " + str(income_histogram.value))
print("Sex histogram Geometric DP release:      " + str(sex_histogram.value))
print("Education histogram Geometric DP release:" + str(education_histogram.value))