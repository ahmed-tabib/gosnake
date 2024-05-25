package main

import (
	"context"
	"sync"
	"time"

	"automation.com/cachesnake"
	"github.com/valyala/fasthttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoSubdomain struct {
	Value       string             `bson:"value"`
	SubdomainID primitive.ObjectID `bson:"_id"`
	ProgramID   primitive.ObjectID `bson:"parent_program"`
}

type MongoProgram struct {
	ProgramName    string   `bson:"name"`
	ProgramURL     string   `bson:"url"`
	Platform       string   `bson:"platform"`
	OffersBounties bool     `bson:"offers_bounties"`
	InScope        []string `bson:"inscope"`
	OutOfScope     []string `bson:"outofscope"`
}

func FetchSubdomains(program_list *map[string]*cachesnake.BBProgram, db_client *mongo.Client, max_count int, cfg *Config) ([]*cachesnake.Subdomain, error) {
	// Fetch the subdomains from the database
	database := db_client.Database(cfg.Mongo.DBName)
	subdomain_collection := database.Collection(cfg.Mongo.SubdomainCollName)

	filter := bson.D{{}} //"last_fetched_wcp", bson.D{{"$lte", time.Now().Add(-1 * cfg.Crawler.MinSubdomainAge)}}}}
	opts := options.Find().SetLimit(int64(max_count)).SetSort(bson.D{{"last_fetched_wcp", 1}})

	cursor, err := subdomain_collection.Find(context.TODO(), filter, opts)

	if err != nil {
		return nil, err
	}

	var db_results []MongoSubdomain
	err = cursor.All(context.TODO(), &db_results)
	if err != nil {
		return nil, err
	}

	if len(db_results) == 0 {
		return nil, nil
	}

	// Mark the time the subdomains were fetched
	bulk_write_operations := make([]mongo.WriteModel, 0, len(db_results))
	for _, s := range db_results {
		update := mongo.NewUpdateOneModel().
			SetFilter(bson.D{{"_id", s.SubdomainID}}).
			SetUpdate(bson.D{{"$currentDate", bson.D{{"last_fetched_wcp", bson.D{{"$type", "date"}}}}}})
		bulk_write_operations = append(bulk_write_operations, update)
	}

	_, err = subdomain_collection.BulkWrite(context.TODO(), bulk_write_operations)
	if err != nil {
		return nil, err
	}

	// Create cachesnake subdomain objects & fetch/assign their corresponding program
	result := make([]*cachesnake.Subdomain, 0, len(db_results))
	for _, s := range db_results {
		program, in_map := (*program_list)[s.ProgramID.Hex()]

		// if the program is not in the list, fetch it from the database
		if !in_map {
			// fetch from db
			program_collection := database.Collection(cfg.Mongo.ProgramCollName)
			filter := bson.D{{"_id", s.ProgramID}}
			fetched_program := MongoProgram{}
			err = program_collection.FindOne(context.TODO(), filter).Decode(&fetched_program)

			// if we have an error, make a mock program
			if err != nil {
				program = &cachesnake.BBProgram{
					ProgramName:    "N/A",
					ProgramURL:     "N/A",
					Platform:       "N/A",
					OffersBounties: false,
					InScope:        []string{},
					OutOfScope:     []string{},
				}
			} else {
				program = &cachesnake.BBProgram{
					ProgramName:    fetched_program.ProgramName,
					ProgramURL:     fetched_program.ProgramURL,
					Platform:       fetched_program.Platform,
					OffersBounties: fetched_program.OffersBounties,
					InScope:        fetched_program.InScope,
					OutOfScope:     fetched_program.OutOfScope,
				}
			}

			// cache the program
			(*program_list)[s.ProgramID.Hex()] = program
		}

		subdomain := cachesnake.Subdomain{
			Value:         s.Value,
			ParentProgram: program,
			LastRequested: time.Now(),
			SubLock:       sync.Mutex{},
			CookieList:    make([]*fasthttp.Cookie, 0),
		}
		result = append(result, &subdomain)
	}

	err = cursor.Close(context.TODO())
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	} else {
		return result, nil
	}
}
