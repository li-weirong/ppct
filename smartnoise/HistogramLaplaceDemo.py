import os
import opendp.smartnoise.core as sn
data_path = os.path.join('.', 'data', 'PUMS.csv')
var_names = ["age", "sex", "educ", "race", "income", "married"] #字段名称
income_edges = list(range(0, 100000, 10000)) #收入分成10段
education_categories = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", 
                        "11", "12", "13", "14", "15", "16"]
#使用拉普拉斯机制需要关闭protect_floating_point
with sn.Analysis(protect_floating_point=False) as analysis:
    data = sn.Dataset(path = data_path, column_names = var_names)
    nsize = 1000
    income_prep = sn.histogram(sn.to_int(data['income'], lower=0, upper=100000),
            edges=income_edges) #数据分箱
    income_histogram = sn.laplace_mechanism(income_prep, 
            privacy_usage={"epsilon": 0.5, "delta": .000001}) #delta越小，安全性越高
    sex_prep = sn.histogram(sn.to_bool(data['sex'], true_label="0"))
    sex_histogram = sn.laplace_mechanism(sex_prep, 
            privacy_usage={"epsilon": 0.5, "delta": .000001})
    education_prep = sn.histogram(data['educ'],
            categories = education_categories, 
            null_value = "-1") #如果数据不再categories范围则设为-1
    education_histogram = sn.laplace_mechanism(education_prep, 
            privacy_usage={"epsilon": 0.5, "delta": .000001})
analysis.release()
print("Income histogram Laplace DP release:     " + str(income_histogram.value))
print("Sex histogram Laplace DP release:        " + str(sex_histogram.value))
print("Education histogram Laplace DP release:  " + str(education_histogram.value))