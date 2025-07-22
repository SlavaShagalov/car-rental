package repository

const (
	insertPaymentQuery = `insert into payments(payment_uid, status, price) 
values (:payment_uid, :status, :price)
returning *;`

	selectPaymentQuery = `select *
from payments
where payment_uid = $1 limit 1;`

	updatePaymentStatusQuery = `update payments
set status = $2
where payment_uid = $1;`
)
