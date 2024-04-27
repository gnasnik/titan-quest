package dao

import (
	"context"
	"fmt"
	"github.com/gnasnik/titan-quest/core/generated/model"
)

func AddOperationLog(ctx context.Context, log *model.OperationLog) error {
	_, err := DB.NamedExecContext(ctx, fmt.Sprintf(
		`INSERT INTO operation_log (title, business_type, method, request_method, operator_type, operator_username,
				operator_url, operator_ip, operator_location, operator_param, json_result, status, error_msg, created_at, updated_at)
			VALUES (:title, :business_type, :method, :request_method, :operator_type, :operator_username, :operator_url, 
			    :operator_ip, :operator_location, :operator_param, :json_result, :status, :error_msg, now(), now());`,
	), log)
	return err
}

func ListOperationLog(ctx context.Context, option QueryOption) ([]*model.OperationLog, int64, error) {
	var args []interface{}
	var total int64
	var out []*model.OperationLog

	limit := option.PageSize
	offset := option.Page
	if option.PageSize <= 0 {
		limit = 50
	}
	if option.Page > 0 {
		offset = limit * (option.Page - 1)
	}

	err := DB.GetContext(ctx, &total, fmt.Sprintf(
		`SELECT count(*) FROM operation_log`,
	), args)
	if err != nil {
		return nil, 0, err
	}

	err = DB.SelectContext(ctx, &out, fmt.Sprintf(
		`SELECT * FROM operation_log LIMIT %d OFFSET %d`, limit, offset,
	), args...)
	if err != nil {
		return nil, 0, err
	}

	return out, total, err
}
